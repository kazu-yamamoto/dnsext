module DNSC.Iterative (
  -- * query interfaces
  runQuery,
  runQuery1,
  newContext,
  runIterative,
  rootNS, Delegation,
  QueryError (..),
  printResult,

  -- * low-level interfaces
  DNSQuery, runDNSQuery,
  query, query1, iterative,
  ) where

import Control.Monad (when, join)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Control.Monad.Trans.Reader (ReaderT (..), asks)
import qualified Data.ByteString.Char8 as B8
import Data.Maybe (mapMaybe, listToMaybe)
import Data.List (isSuffixOf, unfoldr, uncons)
import System.IO (hSetBuffering, stdout, BufferMode (LineBuffering))
import System.Random (randomR, getStdRandom)

import Data.IP (IP (IPv4, IPv6))
import Network.DNS
  (Domain, ResolvConf (..), FlagOp (FlagClear), DNSError, RData (..),
   TYPE(A, NS, AAAA, CNAME), ResourceRecord (ResourceRecord, rrname, rrtype, rdata), DNSMessage)
import qualified Network.DNS as DNS

import DNSC.RootServers (rootServers)


type Name = String

validate :: Name -> Bool
validate = not . null
-- validate = all (not . null) . splitOn "."

-- nomalize (domain) name to absolute name
normalize :: Name -> Maybe Name
normalize "." = Just "."
normalize s
  -- empty part is not valid, empty name is not valid
  | validate rn   = Just nn
  | otherwise     = Nothing  -- not valid
  where
    (rn, nn) | "." `isSuffixOf` s = (init s, s)
             | otherwise          = (s, s ++ ".")

-- get parent name for valid name
parent :: String -> String
parent n
  | null dotp    =  error "parent: empty name is not valid."
  | dotp == "."  =  "."  -- parent of "." is "."
  | otherwise    =  tail dotp
  where
    dotp = dropWhile (/= '.') n

-- get domain list for normalized name
domains :: Name -> [Name]
domains "."  = []
domains name
  | "." `isSuffixOf` name = name : unfoldr parent_ name
  | otherwise             = error "domains: normalized name is required."
  where
    parent_ n
      | p == "."   =  Nothing
      | otherwise  =  Just (p, p)
      where
        p = parent n

-----

data Context =
  Context
  { trace_ :: Bool
  , disableV6NS_ :: Bool
  }
  deriving Show

data QueryError
  = DnsError DNSError
  | NotResponse DNS.QorR DNSMessage
  | HasError DNS.RCODE DNSMessage
  | InvalidEDNS DNS.EDNSheader DNSMessage
  deriving Show

type DNSQuery = ExceptT QueryError (ReaderT Context IO)

---

{-
反復検索の概要

目的のドメインに対して、TLD(トップレベルドメイン) から子ドメインの方向へと順に、権威サーバへの A クエリを繰り返す.
権威サーバへの A クエリの返答メッセージには、
authority セクションに、次の権威サーバの名前 (NS) が、
additional セクションにその名前に対するアドレス (A および AAAA) が入っている.
この情報を使って、繰り返し、子ドメインへの検索を行なう.
検索ドメインの初期値はTLD、権威サーバの初期値はルートサーバとなる.
 -}

newContext :: Bool -> Bool -> IO Context
newContext trace disableV6NS = do
  when trace $ hSetBuffering stdout LineBuffering
  return Context { trace_ = trace, disableV6NS_ = disableV6NS }

dnsQueryT :: (Context -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT = ExceptT . ReaderT

runDNSQuery :: DNSQuery a -> Context -> IO (Either QueryError a)
runDNSQuery = runReaderT . runExceptT

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwE . DnsError

handleResponseError :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError e f msg
  | DNS.qOrR flags /= DNS.QR_Response      =  e $ NotResponse (DNS.qOrR flags) msg
  | DNS.rcode flags /= DNS.NoErr           =  e $ HasError (DNS.rcode flags) msg
  | DNS.ednsHeader msg == DNS.InvalidEDNS  =  e $ InvalidEDNS (DNS.ednsHeader msg) msg
  | otherwise                              =  f msg
  where
    flags = DNS.flags $ DNS.header msg
-- responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- responseErrDNSQuery = handleResponseError throwE return  :: DNSMessage -> DNSQuery DNSMessage

withNormalized :: Name -> (Name -> DNSQuery a) -> Context -> IO (Either QueryError a)
withNormalized n action =
  runDNSQuery $
  action =<< maybe (throwDnsError DNS.IllegalDomain) return (normalize n)

runQuery :: Context -> Name -> TYPE -> IO (Either QueryError DNSMessage)
runQuery cxt n typ = withNormalized n (`query` typ) cxt

runQuery1 :: Context -> Name -> TYPE -> IO (Either QueryError DNSMessage)
runQuery1 cxt n typ = withNormalized n (`query1` typ) cxt

runIterative :: Context -> Delegation -> Name -> IO (Either QueryError Delegation)
runIterative cxt sa n = withNormalized n (iterative sa) cxt

---

-- 反復検索を使ったクエリ. 結果が CNAME なら繰り返し解決する.
query :: Name -> TYPE -> DNSQuery DNSMessage
query n CNAME = query1 n CNAME
query n typ = do
  msg <- query1 n typ
  let answers = DNS.answer msg

  -- TODO: CNAME 解決の回数制限
  let resolveCNAME cn _cnRR = do
        when (any ((== typ) . rrtype) answers) $ throwDnsError DNS.UnexpectedRDATA  -- CNAME と目的の TYPE が同時に存在した場合はエラー
        x <- query (B8.unpack cn) typ
        return x

  maybe
    (pure msg)
    (uncurry resolveCNAME)
    =<< liftIO (selectCNAME $ mapMaybe takeCNAME answers)
  where
    takeCNAME rr@ResourceRecord { rrtype = CNAME, rdata = RD_CNAME cn }
      | rrname rr == B8.pack n  =  Just (cn, rr)
    takeCNAME _                 =  Nothing

    selectCNAME = randomizedSelect

-- 反復検索を使ったクエリ. CNAME は解決しない.
query1 :: Name -> TYPE -> DNSQuery DNSMessage
query1 n typ = do
  lift $ traceLn $ "query1: " ++ show (n, typ)
  nss <- iterative rootNS n
  sa <- selectDelegation nss
  msg <- dnsQueryT $ const $ norec1 sa (B8.pack n) typ
  return msg

type NE a = (a, [a])

-- ドメインに対する NS 委任情報
type Delegation = (NE (Domain, ResourceRecord), [ResourceRecord])

{-# ANN rootNS ("HLint: ignore Use fromMaybe") #-}
rootNS :: Delegation
rootNS =
  maybe
  (error "rootNS: bad configuration.")
  id
  $ uncurry (authorityNS_ (B8.pack ".")) rootServers

-- 反復検索でドメインの NS のアドレスを得る
iterative :: Delegation -> Name -> DNSQuery Delegation
iterative sa n = iterative_ sa $ reverse $ domains n

-- 反復検索の本体
iterative_ :: Delegation -> [Name] -> DNSQuery Delegation
iterative_ nss []     = return nss
iterative_ nss (x:xs) =
  step nss >>=
  maybe
  (iterative_ nss xs)   -- NS が返らない場合は同じ NS の情報で子ドメインへ. 通常のホスト名もこのケース. ex. or.jp, ad.jp
  (`iterative_` xs)
  where
    name = B8.pack x

    step :: Delegation -> DNSQuery (Maybe Delegation)
    step nss_ = do
      sa <- selectDelegation nss_  -- 親ドメインから同じ NS の情報が引き継がれた場合も、NS のアドレスを選択しなおすことで balancing する.
      lift $ traceLn $ "iterative: " ++ show (sa, name)
      msg <- dnsQueryT $ const $ norec1 sa name A
      let result = authorityNS name msg
      return result

-- 選択可能な NS が有るときだけ Just
authorityNS :: Domain -> DNSMessage -> Maybe Delegation
authorityNS dom msg = authorityNS_ dom (DNS.authority msg) (DNS.additional msg)

{-# ANN authorityNS_ ("HLint: ignore Use tuple-section") #-}
authorityNS_ :: Domain -> [ResourceRecord] -> [ResourceRecord] -> Maybe Delegation
authorityNS_ dom auths adds =
  (\x -> (x, adds)) <$> uncons nss
  where
    nss = mapMaybe takeNS auths

    takeNS rr@ResourceRecord { rrtype = NS, rdata = RD_NS ns }
      | rrname rr == dom  =  Just (ns, rr)
    takeNS _              =  Nothing

norec1 :: IP -> Domain -> TYPE -> IO (Either QueryError DNSMessage)
norec1 aserver name typ = do
  rs <- DNS.makeResolvSeed conf
  either (Left . DnsError) (handleResponseError Left Right) <$>
    DNS.withResolver rs ( \resolver -> DNS.lookupRaw resolver name typ )
  where
    conf = DNS.defaultResolvConf
           { resolvInfo = DNS.RCHostName $ show aserver
           , resolvTimeout = 5 * 1000 * 1000
           , resolvRetry = 2
           , resolvQueryControls = DNS.rdFlag FlagClear
           }

-- authority section 内の、Domain に対応する NS レコードが一つも無いときに Nothing
-- そうでなければ、additional section 内の NS の名前に対応する A を利用してアドレスを得る
-- NS の名前に対応する A が無いときには反復検索で解決しに行く (PTR 解決のときには glue レコードが無い)
selectDelegation :: Delegation -> DNSQuery IP
selectDelegation (nss, as) = do
  let selectNS = randomizedSelectN
  (ns, nsRR) <- liftIO $ selectNS nss
  disableV6NS <- lift $ asks disableV6NS_

  let selectA = randomizedSelect
      takeAx :: ResourceRecord -> Maybe (IP, ResourceRecord)
      takeAx rr@ResourceRecord { rrtype = A, rdata = RD_A ipv4 }
        | rrname rr == ns  =  Just (IPv4 ipv4, rr)
      takeAx rr@ResourceRecord { rrtype = AAAA, rdata = RD_AAAA ipv6 }
        | not disableV6NS &&
          rrname rr == ns  =  Just (IPv6 ipv6, rr)
      takeAx _             =  Nothing

      queryAx
        | disableV6NS  =  q4
        | otherwise    =  join $ liftIO $ randomizedSelectN (v4f, [v6f])
        where
          v4f = q4 +? q6 ; v6f = q6 +? q4
          q4 = DNS.answer <$> query1 nsName A
          q6 = DNS.answer <$> query1 nsName AAAA
          qx +? qy = do
            xs <- qx
            if null xs then qy else pure xs
          nsName = B8.unpack ns

      query1AXofNS :: DNSQuery (IP, ResourceRecord)
      query1AXofNS =
        maybe (throwDnsError DNS.IllegalDomain) pure  -- 失敗時: NS に対応する A の返答が空
        =<< liftIO . selectA . mapMaybe takeAx =<< queryAx

  (a, _aRR) <- maybe query1AXofNS return =<< liftIO (selectA $ mapMaybe takeAx as)
  lift $ traceLn $ "selectDelegation: " ++ show (rrname nsRR, (ns, a))

  return a

randomSelect :: Bool
randomSelect = True

randomizedSelectN :: NE a -> IO a
randomizedSelectN
  | randomSelect  =  d
  | otherwise     =  return . fst  -- naive implementation
  where
    d (x, []) = return x
    d (x, xs) = do
      ix <- getStdRandom $ randomR (0, length xs)
      return $ (x:xs) !! ix

randomizedSelect :: [a] -> IO (Maybe a)
randomizedSelect
  | randomSelect  =  d
  | otherwise     =  return . listToMaybe  -- naive implementation
  where
    d []   =  return Nothing
    d [x]  =  return $ Just x
    d xs   =  do
      ix <- getStdRandom $ randomR (0, length xs - 1)
      return $ Just $ xs !! ix

tracePut :: String -> ReaderT Context IO ()
tracePut s = do
  trace <- asks trace_
  when trace $ liftIO $ putStr s

traceLn :: String -> ReaderT Context IO ()
traceLn = tracePut . (++ "\n")

printResult :: Either QueryError DNSMessage -> IO ()
printResult = either print pmsg
  where
    pmsg msg =
      putStr $ unlines $
      ["answer:"] ++
      map show (DNS.answer msg) ++
      [""] ++
      ["authority:"] ++
      map show (DNS.authority msg) ++
      [""] ++
      ["additional:"] ++
      map show (DNS.additional msg) ++
      [""]
