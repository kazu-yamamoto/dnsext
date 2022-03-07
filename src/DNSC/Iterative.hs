module DNSC.Iterative (
  -- * query interfaces
  runQuery,
  runQuery1,
  runIterative,
  rootNS, AuthNS,
  printResult,

  -- * low-level interfaces
  DNSQuery, runDNSQuery,
  query, query1, iterative,
  ) where

import Control.Concurrent (forkIO)
import Control.Monad (when, void)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import qualified Data.ByteString.Char8 as B8
import Data.Maybe (mapMaybe, listToMaybe)
import Data.List (isSuffixOf, unfoldr, intercalate, uncons)
import Data.Bits ((.&.), shiftR)
import Numeric (showHex)
import System.IO (hSetBuffering, stdout, BufferMode (LineBuffering))
import System.Random (randomR, getStdRandom)

import Data.IP (IP (IPv4, IPv6), IPv4, IPv6, fromIPv4, fromIPv6)
import Network.DNS
  (Domain, ResolvConf (..), FlagOp (FlagClear, FlagSet), DNSError, RData (..),
   TYPE(A, PTR), ResourceRecord (ResourceRecord, rrname, rrtype, rdata), DNSMessage)
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

type DNSQuery = ExceptT DNSError IO

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

runDNSQuery :: DNSQuery a -> IO (Either DNSError a)
runDNSQuery q = do
  hSetBuffering stdout LineBuffering
  runExceptT q

withNormalized :: Name -> (Name -> DNSQuery a) -> IO (Either DNSError a)
withNormalized n action = runDNSQuery $ do
  action =<< maybe (throwE DNS.IllegalDomain) return (normalize n)

runQuery :: Name -> TYPE -> IO (Either DNSError DNSMessage)
runQuery n typ = withNormalized n (`query` typ)

-- 反復検索を使ったクエリ. 結果が CNAME なら繰り返し解決する.
query :: Name -> TYPE -> DNSQuery DNSMessage
query n typ = do
  msg <- query1 n typ
  let answers = DNS.answer msg

  -- TODO: CNAME 解決の回数制限
  let resolveCNAME cn cnRR = do
        when (any ((== typ) . rrtype) answers) $ throwE DNS.UnexpectedRDATA
        x <- query (B8.unpack cn) typ
        lift $ cacheRR cnRR
        return x

  maybe
    (pure msg)
    (uncurry resolveCNAME)
    $ listToMaybe $ mapMaybe takeCNAME answers
  where
    takeCNAME (rr@ResourceRecord { rdata = RD_CNAME cn})
      | rrname rr == B8.pack n  =  Just (cn, rr)
    takeCNAME _                 =  Nothing

runQuery1 :: Name -> TYPE -> IO (Either DNSError DNSMessage)
runQuery1 n typ = withNormalized n (`query1` typ)

-- 反復検索を使ったクエリ. CNAME は解決しない.
query1 :: Name -> TYPE -> DNSQuery DNSMessage
query1 n typ = do
  liftIO $ debugLn $ "query1: " ++ show (n, typ)
  nss <- iterative rootNS n
  sa <- selectAuthNS nss
  msg <- ExceptT $ qNorec1 sa (B8.pack n) typ
  liftIO $ mapM_ cacheRR $ DNS.answer msg
  return msg

runIterative :: AuthNS -> Name -> IO (Either DNSError AuthNS)
runIterative sa n = withNormalized n $ iterative sa

type NE a = (a, [a])

-- ドメインに対する複数の NS の情報
type AuthNS = (NE (Domain, ResourceRecord), [ResourceRecord])

rootNS :: AuthNS
rootNS =
  maybe
  (error "rootNS: bad configuration.")
  id
  $ uncurry (authorityNS_ (B8.pack ".")) rootServers

-- 反復検索でドメインの NS のアドレスを得る
iterative :: AuthNS -> Name -> DNSQuery AuthNS
iterative sa n = iterative_ sa $ reverse $ domains n

-- 反復検索の本体
iterative_ :: AuthNS -> [Name] -> DNSQuery AuthNS
iterative_ nss []     = return nss
iterative_ nss (x:xs) =
  step nss >>=
  maybe
  (iterative_ nss xs)   -- NS が返らない場合は同じ NS の情報で子ドメインへ. 通常のホスト名もこのケース. ex. or.jp, ad.jp
  (\nss_ -> iterative_ nss_ xs)
  where
    name = B8.pack x

    step :: AuthNS -> DNSQuery (Maybe AuthNS)
    step nss_ = do
      sa <- selectAuthNS nss_  -- 親ドメインから同じ NS の情報が引き継がれた場合も、NS のアドレスを選択しなおすことで balancing する.
      liftIO $ debugLn $ "iterative: " ++ show (sa, name)
      msg <- ExceptT $ qNorec1 sa name A
      pure $ authorityNS name msg

-- 選択可能な NS が有るときだけ Just
authorityNS :: Domain -> DNSMessage -> Maybe AuthNS
authorityNS dom msg = authorityNS_ dom (DNS.authority msg) (DNS.additional msg)

authorityNS_ :: Domain -> [ResourceRecord] -> [ResourceRecord] -> Maybe AuthNS
authorityNS_ dom auths adds =
  fmap (\x -> (x, adds)) $ uncons nss
  where
    nss = mapMaybe takeNS auths

    takeNS (rr@ResourceRecord { rdata = RD_NS ns})
      | rrname rr == dom  =  Just (ns, rr)
    takeNS _              =  Nothing

qNorec1 :: IP -> Domain -> TYPE -> IO (Either DNSError DNSMessage)
qNorec1 aserver name typ = do
  rs <- DNS.makeResolvSeed conf
  DNS.withResolver rs $ \resolver -> DNS.lookupRaw resolver name typ
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
selectAuthNS :: AuthNS -> DNSQuery IP
selectAuthNS (nss, as) = do
  (ns, nsRR) <- liftIO $ selectNS nss

  let resolveNS :: DNSQuery IP
      resolveNS = do
        let doCache (a, aRR)
              | rrname nsRR == B8.pack "." = return a  -- root は cache しない
              | otherwise  = do
                  void $ forkIO $ cacheVerifiedTh aRR nsRR  -- verify を別スレッドに切り離す.
                  return a
        liftIO (selectA $ mapMaybe (takeAx ns) as) >>= maybe (query1AofNS ns) (liftIO . doCache)

      -- NS 逆引きの verify は別スレッドに切り離してキャッシュの可否だけに利用する.
      -- たとえば e.in-addr-servers.arpa.  は正引きして逆引きすると  anysec.apnic.net. になって一致しない.
      cacheVerifiedTh :: ResourceRecord -> ResourceRecord -> IO ()
      cacheVerifiedTh aRR_ nsRR_ =
        either (debugLn . ("cacheVerifiedNS: verify query: " ++) . show) pure =<<
        runExceptT (cacheVerifiedNS aRR_ nsRR_)

  a <- resolveNS
  liftIO $ debugLn $ "selectAuthNS: " ++ show (rrname nsRR, (ns, a))
  return a

  where
    query1AofNS :: Domain -> DNSQuery IP
    query1AofNS ns =
      maybe (throwE DNS.IllegalDomain) (pure . fst)  -- 失敗時: NS に対応する A の返答が空
      . listToMaybe . mapMaybe (takeAx ns) . DNS.answer
      =<< query1 (B8.unpack ns) A

    takeAx ns (rr@ResourceRecord { rdata = RD_A ipv4 })
      | rrname rr == ns  =  Just (IPv4 ipv4, rr)
    takeAx ns (rr@ResourceRecord { rdata = RD_AAAA ipv6 })
      | rrname rr == ns  =  Just (IPv6 ipv6, rr)
    takeAx _  _          =  Nothing

cacheVerifiedNS :: ResourceRecord -> ResourceRecord -> DNSQuery ()
cacheVerifiedNS aRR nsRR= do
  good <- verifyA aRR
  liftIO $ if good
           then do cacheRR nsRR
                   cacheRR aRR
           else    debugLn $ unlines ["cacheVerifiedNS: reverse lookup inconsistent: ", show aRR, show nsRR]

randomSelect :: Bool
randomSelect = True

selectNS :: NE a -> IO a
selectNS rs
  | randomSelect  =  randomizedSelectN rs
  | otherwise     =  return $ fst rs  -- naive implementation

selectA :: [a] -> IO (Maybe a)
selectA as
  | randomSelect  =  randomizedSelect as
  | otherwise     =  do
      -- when (null as) $ putStrLn $ "selectA: warning: zero address list is passed." -- no glue record?
      -- naive implementation
      return $ listToMaybe as

randomizedSelectN :: NE a -> IO a
randomizedSelectN = d
  where
    d (x, []) = return x
    d (x, xs) = do
      ix <- getStdRandom $ randomR (0, length xs)
      return $ (x:xs) !! ix

randomizedSelect :: [a] -> IO (Maybe a)
randomizedSelect = d
  where
    d []   =  return Nothing
    d [x]  =  return $ Just x
    d xs   =  do
      ix <- getStdRandom $ randomR (0, length xs - 1)
      return $ Just $ xs !! ix

v4PtrDomain :: IPv4 -> Name
v4PtrDomain ipv4 = dom
  where
    octets = reverse $ fromIPv4 ipv4
    dom = intercalate "." $ map show octets ++ ["in-addr.arpa."]

v6PtrDomain :: IPv6 -> Name
v6PtrDomain ipv6 = dom
  where
    w16hx w =
      [ (w `shiftR` 12) .&. 0x0f
      , (w `shiftR`  8) .&. 0x0f
      , (w `shiftR`  4) .&. 0x0f
      ,  w              .&. 0x0f
      ]
    hxs = reverse $ concatMap w16hx $ fromIPv6 ipv6
    showH x = showHex x ""
    dom = intercalate "." $ map showH hxs ++ ["ip6.arpa."]

verifyA :: ResourceRecord -> DNSQuery Bool
verifyA aRR@(ResourceRecord { rrname = ns }) =
  case rdata aRR of
    RD_A ipv4     ->  resolvePTR $ v4PtrDomain ipv4
    RD_AAAA ipv6  ->  resolvePTR $ v6PtrDomain ipv6
    _             ->  return False
  where
    resolvePTR ptrDom = do
      msg <- qSystem ptrDom PTR  -- query が循環しないようにシステムのレゾルバを使う
      let mayPTR = listToMaybe $ mapMaybe takePTR $ DNS.answer msg
      maybe (pure True) checkPTR mayPTR  -- 逆引きが割り当てられていないときは通す

    checkPTR (ptr, ptrRR) = do
      let good =  ptr == ns
      when good $ liftIO $ do
        cacheRR ptrRR
        debugLn $ "verifyA: verification pass: " ++ show ns
      return good
    takePTR (rr@ResourceRecord { rdata = RD_PTR ptr})  =  Just (ptr, rr)
    takePTR _                                          =  Nothing

    qSystem :: Name -> TYPE -> DNSQuery DNSMessage
    qSystem name typ = ExceptT $ do
      rs <- DNS.makeResolvSeed conf
      DNS.withResolver rs $ \resolver -> DNS.lookupRaw resolver (B8.pack name) typ
        where
          conf = DNS.defaultResolvConf
                 { resolvTimeout = 5 * 1000 * 1000
                 , resolvRetry = 2
                 , resolvQueryControls = DNS.rdFlag FlagSet
                 }

cacheRR :: ResourceRecord -> IO ()
cacheRR rr = do
  debugLn $ "cacheRR: " ++ show rr

debug :: Bool
debug = True

debugLn :: String -> IO ()
debugLn = when debug . putStrLn

printResult :: Either DNSError DNSMessage -> IO ()
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
