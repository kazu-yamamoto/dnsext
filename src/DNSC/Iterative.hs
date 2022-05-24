module DNSC.Iterative (
  -- * query interfaces
  runReply,
  runQuery,
  runQuery1,
  newContext,
  runIterative,
  rootNS, Delegation,
  QueryError (..),
  printResult,
  -- * types
  Name,
  NE,
  UpdateCache,
  TimeCache,
  -- * low-level interfaces
  DNSQuery, runDNSQuery,
  replyMessage, reply,
  query, query1, iterative,
  Context (..),
  ) where

-- GHC packages
import Control.Arrow ((&&&))
import Control.Monad (when, join)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Control.Monad.Trans.Reader (ReaderT (..), asks)
import qualified Data.ByteString.Char8 as B8
import Data.Int (Int64)
import Data.Maybe (mapMaybe, listToMaybe)
import Data.List (isSuffixOf, unfoldr, uncons, sortOn)
import qualified Data.Set as Set

-- other packages
import System.Random (randomR, getStdRandom)

-- dns packages
import Data.IP (IP (IPv4, IPv6))
import Network.DNS
  (Domain, ResolvConf (..), FlagOp (FlagClear), DNSError, RData (..), TTL, CLASS,
   TYPE(A, NS, AAAA, CNAME), ResourceRecord (ResourceRecord, rrname, rrtype, rdata),
   DNSHeader, DNSMessage)
import qualified Network.DNS as DNS

-- this package
import DNSC.RootServers (rootServers)
import DNSC.DNSUtil (lookupRaw)
import DNSC.Types (NE, Timestamp)
import qualified DNSC.Log as Log
import DNSC.Cache
  (Ranking (RankAdditional), rankedAnswer, rankedAuthority, rankedAdditional,
   insertSetFromSection, Key, Val, CRSet, Cache)
import qualified DNSC.Cache as Cache


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
  { logLines_ :: Log.Level -> [String] -> IO ()
  , disableV6NS_ :: !Bool
  , lookup_ :: Domain -> TYPE -> CLASS -> IO (Maybe ([ResourceRecord], Ranking))
  , insert_ :: Key -> TTL -> CRSet -> Ranking -> IO ()
  , size_ :: IO Int
  , dump_ :: IO [(Key, (Timestamp, Val))]
  , currentSeconds_ :: IO Timestamp
  , timeString_ :: IO ShowS
  }

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

type UpdateCache =
  (Domain -> TYPE -> CLASS -> IO (Maybe ([ResourceRecord], Ranking)),
   Key -> TTL -> CRSet -> Ranking -> IO (),
   IO Cache)
type TimeCache = (IO Int64, IO ShowS)

newContext :: (Log.Level -> [String] -> IO ()) -> Bool -> UpdateCache -> TimeCache
           -> IO Context
newContext putLines disableV6NS (lk, ins, getCache) (curSec, timeStr) = do
  let cxt = Context
        { logLines_ = putLines, disableV6NS_ = disableV6NS
        , lookup_ = lk, insert_ = ins
        , size_ = Cache.size <$> getCache, dump_ = Cache.dump <$> getCache
        , currentSeconds_ = curSec, timeString_ = timeStr }
  return cxt

dnsQueryT :: (Context -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT = ExceptT . ReaderT

runDNSQuery :: DNSQuery a -> Context -> IO (Either QueryError a)
runDNSQuery = runReaderT . runExceptT

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwE . DnsError

handleResponseError :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError e f msg
  | DNS.qOrR flags /= DNS.QR_Response      =  e $ NotResponse (DNS.qOrR flags) msg
  | DNS.rcode flags `notElem`
    [DNS.NoErr, DNS.NameErr]               =  e $ HasError (DNS.rcode flags) msg
  | DNS.ednsHeader msg == DNS.InvalidEDNS  =  e $ InvalidEDNS (DNS.ednsHeader msg) msg
  | otherwise                              =  f msg
  where
    flags = DNS.flags $ DNS.header msg
-- responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- responseErrDNSQuery = handleResponseError throwE return  :: DNSMessage -> DNSQuery DNSMessage

handleNX :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleNX e f msg
  | DNS.rcode flags == DNS.NameErr         =  e $ HasError (DNS.rcode flags) msg
  | otherwise                              =  f msg
  where
    flags = DNS.flags $ DNS.header msg

withNormalized :: Name -> (Name -> DNSQuery a) -> Context -> IO (Either QueryError a)
withNormalized n action =
  runDNSQuery $
  action =<< maybe (throwDnsError DNS.IllegalDomain) return (normalize n)

runReply :: Context -> DNSHeader -> NE DNS.Question -> IO (Either String DNSMessage)
runReply cxt reqH qs@(DNS.Question bn typ, _) =
  (\ers -> replyMessage ers (DNS.identifier reqH) $ uncurry (:) qs)
  <$> withNormalized (B8.unpack bn) (\n -> reply n typ rd) cxt
  where
    rd = DNS.recDesired $ DNS.flags reqH

runQuery :: Context -> Name -> TYPE -> IO (Either QueryError (Either [ResourceRecord] DNSMessage))
runQuery cxt n typ = withNormalized n (`query` typ) cxt

runQuery1 :: Context -> Name -> TYPE -> IO (Either QueryError DNSMessage)
runQuery1 cxt n typ = withNormalized n (`query1` typ) cxt

runIterative :: Context -> Delegation -> Name -> IO (Either QueryError Delegation)
runIterative cxt sa n = withNormalized n (iterative sa) cxt

---

replyMessage :: Either QueryError [ResourceRecord]
             -> DNS.Identifier -> [DNS.Question]
             -> Either String DNSMessage
replyMessage eas ident rqs =
  either queryError (Right . message DNS.NoErr) eas
  where
    dnsError de = message <$> rcodeDNSError de <*> pure []
    rcodeDNSError e = case e of
      DNS.FormatError       ->  Right DNS.FormatErr
      DNS.ServerFailure     ->  Right DNS.ServFail
      DNS.NameError         ->  Right DNS.NameErr
      DNS.NotImplemented    ->  Right DNS.NotImpl
      DNS.OperationRefused  ->  Right DNS.Refused
      DNS.BadOptRecord      ->  Right DNS.BadVers
      _                     ->  Left $ "DNSError: " ++ show e

    queryError qe = case qe of
      DnsError e      ->  dnsError e
      NotResponse {}  ->  Left "qORr is not response"
      HasError rc _m  ->  Right $ message rc []
      InvalidEDNS {}  ->  Left "Invalid EDNS"

    message rcode rrs =
      res
      { DNS.header = h { DNS.identifier = ident
                       , DNS.flags = f { DNS.authAnswer = False, DNS.rcode = rcode } }
      , DNS.answer = rrs
      , DNS.question = rqs
      }
    res = DNS.defaultResponse
    h = DNS.header res
    f = DNS.flags h

reply :: Name -> TYPE -> Bool -> DNSQuery [ResourceRecord]
reply n typ rd =
  maybe rdQuery pure =<< lift lookupCache_
  where
    replyRank (rrs, rank)
      -- 最も低い ranking は reply の answer に利用しない
      -- https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1
      | rank <= RankAdditional  =  Nothing
      | otherwise               =  Just rrs
    lookupCache_ = (replyRank =<<) <$> lookupCache (B8.pack n) typ

    rdQuery
      | not rd     =  throwE $ HasError DNS.Refused DNS.defaultResponse
      | otherwise  =  withQuery

    withQuery = do
      ((arrs, rn), etm) <- query_ n typ
      let takeX rr
            | rrname rr == rn && rrtype rr == typ   =  Just rr
            | otherwise                             =  Nothing
          refinesX rrs = (ps, ps)
            where
              ps = mapMaybe takeX rrs

      lift $ arrs <$> either return (getSectionWithCache rankedAnswer refinesX) etm

-- 反復検索を使ったクエリ. 結果が CNAME なら繰り返し解決する.
query :: Name -> TYPE -> DNSQuery (Either [ResourceRecord] DNSMessage)
query n typ = snd <$> query_ n typ

type DRRList = [ResourceRecord] -> [ResourceRecord]

query_ :: Name -> TYPE -> DNSQuery ((DRRList, Domain), Either [ResourceRecord] DNSMessage)
query_ n CNAME = (,) (id, B8.pack n) . Right <$> query1 n CNAME
query_ n0 typ  = recCN n0 id
  where
    -- CNAME 以外のタイプの検索について、CNAME のラベルで検索しなおす.
    recCN :: Name -> DRRList -> DNSQuery ((DRRList, Domain), Either [ResourceRecord] DNSMessage)
    recCN n arrs = do
      msg <- query1 n typ
      cname <- lift $ getSectionWithCache rankedAnswer refinesCNAME msg

      -- TODO: CNAME 解決の回数制限
      let resolveCNAME (cn, cnRR) = do
            when (any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg) $
              throwDnsError DNS.UnexpectedRDATA  -- CNAME と目的の TYPE が同時に存在した場合はエラー
            recCN (B8.unpack cn) (arrs . (cnRR :))

      maybe (pure ((arrs, bn), Right msg)) resolveCNAME cname
        where
          bn = B8.pack n
          takeCNAME rr@ResourceRecord { rrtype = CNAME, rdata = RD_CNAME cn }
            | rrname rr == bn         =  Just (cn, rr)
          takeCNAME _                 =  Nothing
          refinesCNAME rrs = (fst <$> uncons ps, map snd ps)
            where ps = mapMaybe takeCNAME rrs

-- 反復検索を使ったクエリ. CNAME は解決しない.
query1 :: Name -> TYPE -> DNSQuery DNSMessage
query1 n typ = do
  lift $ logLn Log.INFO $ "query1: " ++ show (n, typ)
  nss <- iterative rootNS n
  sa <- selectDelegation nss
  lift $ logLn Log.DEBUG $ "query1: norec1: " ++ show (sa, n, typ)
  handleNX throwE return =<< norec1 sa (B8.pack n) typ

-- ドメインに対する NS 委任情報
type Delegation = (NE (Domain, ResourceRecord), [ResourceRecord])

{-# ANN rootNS ("HLint: ignore Use fromMaybe") #-}
{-# ANN rootNS ("HLint: ignore Use tuple-section") #-}
rootNS :: Delegation
rootNS =
  maybe
  (error "rootNS: bad configuration.")
  (flip (,) as)
  $ uncons $ nsList (B8.pack ".") (,) ns
  where
    (ns, as) = rootServers

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

    lookupNS :: ReaderT Context IO (Maybe Delegation)
    lookupNS = do
      m <- lookupCache name NS
      return $ do
        (rrs, _) <- m
        ns <- uncons $ nsList name (,) rrs
        Just (ns, [])

    stepQuery :: Delegation -> DNSQuery (Maybe Delegation)
    stepQuery nss_ = do
      sa <- selectDelegation nss_  -- 親ドメインから同じ NS の情報が引き継がれた場合も、NS のアドレスを選択しなおすことで balancing する.
      lift $ logLn Log.INFO $ "iterative: norec1: " ++ show (sa, name, A)
      msg <- norec1 sa name A
      lift $ delegationWithCache name msg

    step :: Delegation -> DNSQuery (Maybe Delegation)
    step nss_ =
      maybe (stepQuery nss_) (return . Just) =<< lift lookupNS

delegationWithCache :: Domain -> DNSMessage -> ReaderT Context IO (Maybe Delegation)
delegationWithCache dom msg =
  -- 選択可能な NS が有るときだけ Just
  mapM action $ uncons nss
  where
    action xs = do
      cacheNS
      cacheAdds
      return (xs, adds)
    (nss, cacheNS) = getSection rankedAuthority refinesNS msg
      where refinesNS = unzip . nsList dom (\ns rr -> ((ns, rr), rr))
    (adds, cacheAdds) = getSection rankedAdditional refinesAofNS msg
      where refinesAofNS rrs = (rrs, sortOn (rrname &&& rrtype) $ filter match rrs)
            match rr = rrtype rr `elem` [A, AAAA] && rrname rr `Set.member` nsSet
            nsSet = Set.fromList $ map fst nss

nsList :: Domain -> (Domain ->  ResourceRecord -> a)
       -> [ResourceRecord] -> [a]
nsList dom h = mapMaybe takeNS
  where
    takeNS rr@ResourceRecord { rrtype = NS, rdata = RD_NS ns }
      | rrname rr == dom  =  Just $ h ns rr
    takeNS _              =  Nothing

norec1 :: IP -> Domain -> TYPE -> DNSQuery DNSMessage
norec1 aserver name typ = dnsQueryT $ \cxt -> do
  now <- currentSeconds_ cxt
  rs <- DNS.makeResolvSeed conf
  either (Left . DnsError) (handleResponseError Left Right) <$>
    DNS.withResolver rs ( \resolver -> lookupRaw now resolver name typ )
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

      refinesAx rrs = (ps, map snd ps)
        where ps = mapMaybe takeAx rrs

      lookupAx
        | disableV6NS  =  lk4
        | otherwise    =  join $ liftIO $ randomizedSelectN (lk46, [lk64])
        where
          lk46 = lk4 +? lk6
          lk64 = lk6 +? lk4
          lk4 = lookupCache ns A
          lk6 = lookupCache ns AAAA
          lx +? ly = maybe ly (return . Just) =<< lx

      query1Ax
        | disableV6NS  =  q4
        | otherwise    =  join $ liftIO $ randomizedSelectN (q46, [q64])
        where
          q46 = q4 +!? q6 ; q64 = q6 +!? q4
          q4 = querySection A
          q6 = querySection AAAA
          qx +!? qy = do
            xs <- qx
            if null xs then qy else pure xs
          querySection typ = lift . getSectionWithCache rankedAnswer refinesAx =<< query1 nsName typ
          nsName = B8.unpack ns

      resolveAXofNS :: DNSQuery (IP, ResourceRecord)
      resolveAXofNS =
        maybe (throwDnsError DNS.IllegalDomain) pure  -- 失敗時: NS に対応する A の返答が空
        =<< liftIO . selectA =<< maybe query1Ax (pure . mapMaybe takeAx . fst) =<< lift lookupAx

  (a, _aRR) <- maybe resolveAXofNS return =<< liftIO (selectA $ mapMaybe takeAx as)
  lift $ logLn Log.DEBUG $ "selectDelegation: " ++ show (rrname nsRR, (ns, a))

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

---

lookupCache :: Domain -> TYPE -> ReaderT Context IO (Maybe ([ResourceRecord], Ranking))
lookupCache dom typ = do
  lookupRRs <- asks lookup_
  result <- liftIO $ lookupRRs dom typ DNS.classIN
  logLn Log.DEBUG $ "lookupCache: " ++ unwords [show dom, show typ, show DNS.classIN, ":",
                                        maybe "miss" (\ (_, rank) -> "hit: " ++ show rank) result]
  return result

getSection :: (m -> ([ResourceRecord], Ranking))
           -> ([ResourceRecord] -> (a, [ResourceRecord]))
           -> m -> (a, ReaderT Context IO ())
getSection getP refines msg =
  withSection $ getP msg
  where
    withSection (rrs0, rank) = (result, cacheSection srrs rank)
      where (result, srrs) = refines rrs0

getSectionWithCache :: (m -> ([ResourceRecord], Ranking))
                    -> ([ResourceRecord] -> (a, [ResourceRecord]))
                    -> m -> ReaderT Context IO a
getSectionWithCache get refines msg = do
  let (res, doCache) = getSection get refines msg
  doCache
  return res

cacheSection :: [ResourceRecord] -> Ranking -> ReaderT Context IO ()
cacheSection rs rank =
  uncurry cacheRRSet $ insertSetFromSection rs rank
  where
    putRRSet ((kp, crs), r) =
      logLines Log.DEBUG
      [ "cacheRRSet: " ++ show (kp, r)
      , "  " ++ show crs ]
    putInvalidRRS rrs =
      logLines Log.NOTICE $
      "invalid RR set:" :
      map (("  " ++) . show) rrs
    cacheRRSet errRRSs rrss = do
      mapM_ putInvalidRRS errRRSs
      mapM_ putRRSet rrss
      insertRRSet <- uncurry . uncurry . uncurry <$> asks insert_
      mapM_ (liftIO . insertRRSet) rrss

---

logLines :: Log.Level -> [String] -> ReaderT Context IO ()
logLines level xs = do
  putLines <- asks logLines_
  liftIO $ putLines level xs

logLn :: Log.Level -> String -> ReaderT Context IO ()
logLn level = logLines level . (:[])

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
