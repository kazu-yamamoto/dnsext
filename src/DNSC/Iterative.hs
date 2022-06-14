module DNSC.Iterative (
  -- * resolve interfaces
  getReplyMessage,
  runResolve,
  runResolveJust,
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
  replyMessage, replyAnswer,
  resolve, resolveJust, iterative,
  Context (..),
  normalizeName,
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
import Data.Maybe (listToMaybe)
import Data.List (isSuffixOf, unfoldr, uncons, sortOn)
import qualified Data.Set as Set

-- other packages
import System.Random (randomR, getStdRandom)

-- dns packages
import Data.IP (IP (IPv4, IPv6))
import Network.DNS
  (Domain, ResolvConf (..), FlagOp (FlagClear), DNSError, RData (..), TTL, CLASS,
   TYPE(A, NS, AAAA, CNAME), ResourceRecord (ResourceRecord, rrname, rrtype, rdata),
   RCODE, DNSHeader, DNSMessage)
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

normalizeName :: Name -> Maybe Name
normalizeName = normalize

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
  , insert_ :: Key -> TTL -> CRSet -> Ranking -> IO ()
  , getCache_ :: IO Cache
  , size_ :: IO Int
  , dump_ :: IO [(Key, (Timestamp, Val))]
  , currentSeconds_ :: IO Timestamp
  , timeString_ :: IO ShowS
  }

data QueryError
  = DnsError DNSError
  | NotResponse DNS.QorR DNSMessage
  | InvalidEDNS DNS.EDNSheader DNSMessage
  | HasError DNS.RCODE DNSMessage
  deriving Show

type DNSQuery = ExceptT QueryError (ReaderT Context IO)

---

{-
反復検索の概要

目的のドメインに対して、TLD(トップレベルドメイン) から子ドメインの方向へと順に、権威サーバへの A クエリを繰り返す.
権威サーバへの A クエリの返答メッセージには、
authority セクションに、次の権威サーバ群の名前 (NS) が、
additional セクションにその名前に対するアドレス (A および AAAA) が入っている.
この情報を使って、繰り返し、子ドメインへの検索を行なう.
検索ドメインの初期値はTLD、権威サーバ群の初期値はルートサーバとなる.
 -}

type UpdateCache =
  (Domain -> TYPE -> CLASS -> IO (Maybe ([ResourceRecord], Ranking)),
   Key -> TTL -> CRSet -> Ranking -> IO (),
   IO Cache)
type TimeCache = (IO Int64, IO ShowS)

newContext :: (Log.Level -> [String] -> IO ()) -> Bool -> UpdateCache -> TimeCache
           -> IO Context
newContext putLines disableV6NS (_lk, ins, getCache) (curSec, timeStr) = do
  let cxt = Context
        { logLines_ = putLines, disableV6NS_ = disableV6NS
        , insert_ = ins, getCache_ = getCache
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
  | DNS.ednsHeader msg == DNS.InvalidEDNS  =  e $ InvalidEDNS (DNS.ednsHeader msg) msg
  | DNS.rcode flags `notElem`
    [DNS.NoErr, DNS.NameErr]               =  e $ HasError (DNS.rcode flags) msg
  | otherwise                              =  f msg
  where
    flags = DNS.flags $ DNS.header msg
-- responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- responseErrDNSQuery = handleResponseError throwE return  :: DNSMessage -> DNSQuery DNSMessage

withNormalized :: Name -> (Name -> DNSQuery a) -> Context -> IO (Either QueryError a)
withNormalized n action =
  runDNSQuery $
  action =<< maybe (throwDnsError DNS.IllegalDomain) return (normalize n)

-- 返答メッセージを作る
getReplyMessage :: Context -> DNSHeader -> NE DNS.Question -> IO (Either String DNSMessage)
getReplyMessage cxt reqH qs@(DNS.Question bn typ, _) =
  (\ers -> replyMessage ers (DNS.identifier reqH) $ uncurry (:) qs)
  <$> withNormalized (B8.unpack bn) (\n -> replyAnswer n typ rd) cxt
  where
    rd = DNS.recDesired $ DNS.flags reqH

-- 最終的な解決結果を得る
runResolve :: Context -> Name -> TYPE
           -> IO (Either QueryError (([ResourceRecord] -> [ResourceRecord], Domain), Either (RCODE, [ResourceRecord]) DNSMessage))
runResolve cxt n typ = withNormalized n (`resolve` typ) cxt

-- 権威サーバーからの解決結果を得る
runResolveJust :: Context -> Name -> TYPE -> IO (Either QueryError (DNSMessage, Delegation))
runResolveJust cxt n typ = withNormalized n (`resolveJust` typ) cxt

-- 反復後の委任情報を得る
runIterative :: Context -> Delegation -> Name -> IO (Either QueryError Delegation)
runIterative cxt sa n = withNormalized n (iterative sa) cxt

---

replyMessage :: Either QueryError (RCODE, [ResourceRecord])
             -> DNS.Identifier -> [DNS.Question]
             -> Either String DNSMessage
replyMessage eas ident rqs =
  either queryError (Right . uncurry message) eas
  where
    dnsError de = message <$> rcodeDNSError de <*> pure []
    rcodeDNSError e = case e of
      DNS.FormatError       ->  Right DNS.FormatErr
      DNS.ServerFailure     ->  Right DNS.ServFail
      DNS.NotImplemented    ->  Right DNS.NotImpl
      DNS.OperationRefused  ->  Right DNS.Refused
      DNS.BadOptRecord      ->  Right DNS.BadVers
      _                     ->  Left $ "DNSError: " ++ show e

    queryError qe = case qe of
      DnsError e      ->  dnsError e
      NotResponse {}  ->  Left "qORr is not response"
      InvalidEDNS {}  ->  Left "Invalid EDNS"
      HasError rc _m  ->  Right $ message rc []

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

-- 反復検索を使って返答メッセージ用の結果コードと応答セクションを得る.
replyAnswer :: Name -> TYPE -> Bool -> DNSQuery (RCODE, [ResourceRecord])
replyAnswer n typ rd = rdQuery
  where
    rdQuery
      | not rd     =  throwE $ HasError DNS.Refused DNS.defaultResponse
      | otherwise  =  withQuery

    withQuery = do
      ((aRRs, _rn), etm) <- resolve n typ
      let answer msg = (DNS.rcode $ DNS.flags $ DNS.header msg, DNS.answer msg)

      (rcode, as) <- return $ either id answer etm
      return (rcode, aRRs as)

maxCNameChain :: Int
maxCNameChain = 16

type DRRList = [ResourceRecord] -> [ResourceRecord]

{- 反復検索を使って最終的な権威サーバーからの DNSMessage を得る.
   目的の TYPE の RankAnswer 以上のキャッシュ読み出しが得られた場合はそれが結果となる.
   目的の TYPE が CNAME 以外の場合、結果が CNAME なら繰り返し解決する. その際に CNAME レコードのキャッシュ書き込みを行なう.
   目的の TYPE の結果レコードのキャッシュ書き込みは行なわない. -}
resolve :: Name -> TYPE -> DNSQuery ((DRRList, Domain), Either (RCODE, [ResourceRecord]) DNSMessage)
resolve n0 typ
  | typ == CNAME  =  justCNAME n0
  | otherwise     =  recCNAMEs 0 n0 id
  where
    justCNAME n = do
      let noCache = do
            (msg, _nss) <- resolveJust n CNAME
            lift $ cacheAnswer bn msg
            pure ((id, bn), Right msg)

      maybe
        noCache
        (\(_cn, cnRR) -> pure ((id, bn), Left (DNS.NoErr, [cnRR])))  {- target RR is not CNAME destination but CNAME, so NoErr -}
        =<< lift (lookupCNAME bn)

        where
          bn = B8.pack n

    -- CNAME 以外のタイプの検索について、CNAME のラベルで検索しなおす.
    recCNAMEs :: Int -> Name -> DRRList -> DNSQuery ((DRRList, Domain), Either (RCODE, [ResourceRecord]) DNSMessage)
    recCNAMEs cc n aRRs
      | cc > mcc  = lift (logLn Log.NOTICE $ "query: cname chain limit exceeded: " ++ show (n0, typ))
                    *> throwDnsError DNS.ServerFailure
      | otherwise = do
      let recCNAMEs_ (cn, cnRR) = recCNAMEs (succ cc) (B8.unpack cn) (aRRs . (cnRR :))
          noCache = do
            (msg, _nss) <- resolveJust n typ
            cname <- lift $ getSectionWithCache rankedAnswer refinesCNAME msg

            let resolveCNAME cnPair = do
                  when (any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg) $
                    throwDnsError DNS.UnexpectedRDATA  -- CNAME と目的の TYPE が同時に存在した場合はエラー
                  recCNAMEs_ cnPair

            maybe (lift $ cacheAnswer bn msg >> pure ((aRRs, bn), Right msg)) resolveCNAME cname

          noTypeCache =
            maybe
            noCache
            recCNAMEs_ {- recurse with cname cache -}
            =<< lift (lookupCNAME bn)

      maybe
        noTypeCache
        (\tyRRs -> pure ((aRRs, bn), Left (DNS.NoErr, tyRRs) {- including NODATA case. -})) {- return cached result with target typ -}
        =<< lift (lookupType bn typ)

        where
          mcc = maxCNameChain
          bn = B8.pack n
          refinesCNAME rrs = (fst <$> uncons ps, map snd ps)
            where ps = cnameList bn (,) rrs

    lookupCNAME bn = do
      mayRRs <- lookupType bn CNAME
      return $ do
        rrs <- mayRRs
        fst <$> uncons (cnameList bn (,) rrs)

    cacheAnswer dom msg = getSectionWithCache rankedAnswer refinesX msg
      where
        refinesX rrs = ((), ps)
          where
            ps = filter isX rrs
            isX rr = rrname rr == dom && rrtype rr == typ

    cnameList dom h = foldr takeCNAME []
      where
        takeCNAME rr@ResourceRecord { rrtype = CNAME, rdata = RD_CNAME cn } xs
          | rrname rr == dom  =  h cn rr : xs
        takeCNAME _      xs   =  xs

    lookupType bn t = (replyRank =<<) <$> lookupCache bn t
    replyRank (rrs, rank)
      -- 最も低い ranking は reply の answer に利用しない
      -- https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1
      | rank <= RankAdditional  =  Nothing
      | otherwise               =  Just rrs

maxNotSublevelDelegation :: Int
maxNotSublevelDelegation = 16

-- 反復検索を使って最終的な権威サーバーからの DNSMessage とその委任情報を得る. CNAME は解決しない.
resolveJust :: Name -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJust = resolveJustDC 0

resolveJustDC :: Int -> Name -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJustDC dc n typ
  | dc > mdc   = lift (logLn Log.NOTICE $ "resolve-just: not sub-level delegation limit exceeded: " ++ show (n, typ))
                 *> throwDnsError DNS.ServerFailure
  | otherwise  = do
  lift $ logLn Log.INFO $ "resolve-just: " ++ "dc=" ++ show dc ++ ", " ++ show (n, typ)
  nss <- iterative rootNS n
  sa <- selectDelegation dc nss
  lift $ logLn Log.DEBUG $ "resolve-just: norec: " ++ show (sa, n, typ)
  (,) <$> norec sa (B8.pack n) typ <*> pure nss
    where
      mdc = maxNotSublevelDelegation

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

-- 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威権威サーバー群を見つける
iterative :: Delegation -> Name -> DNSQuery Delegation
iterative sa n = iterative_ 0 sa $ reverse $ domains n

iterative_ :: Int -> Delegation -> [Name] -> DNSQuery Delegation
iterative_ _  nss []     = return nss
iterative_ dc nss (x:xs) =
  step nss >>=
  maybe
  (recurse nss xs)   -- NS が返らない場合は同じ NS の情報で子ドメインへ. 通常のホスト名もこのケース. ex. or.jp, ad.jp
  (`recurse` xs)
  where
    recurse = iterative_ dc  {- sub-level delegation. increase dc only not sub-level case. -}
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
      sa <- selectDelegation dc nss_  -- 親ドメインから同じ NS の情報が引き継がれた場合も、NS のアドレスを選択しなおすことで balancing する.
      lift $ logLn Log.INFO $ "iterative: norec: " ++ show (sa, name, A)
      msg <- norec sa name A
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
nsList dom h = foldr takeNS []
  where
    takeNS rr@ResourceRecord { rrtype = NS, rdata = RD_NS ns } xs
      | rrname rr == dom  =  h ns rr : xs
    takeNS _         xs   =  xs

-- 権威サーバーから答えの DNSMessage を得る. 再起検索フラグを落として問い合わせる.
norec :: IP -> Domain -> TYPE -> DNSQuery DNSMessage
norec aserver name typ = dnsQueryT $ \cxt -> do
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
selectDelegation :: Int -> Delegation -> DNSQuery IP
selectDelegation dc (nss, as) = do
  let selectNS = randomizedSelectN
  (ns, nsRR) <- liftIO $ selectNS nss
  disableV6NS <- lift $ asks disableV6NS_

  let selectA = randomizedSelect
      takeAx :: ResourceRecord -> [(IP, ResourceRecord)] -> [(IP, ResourceRecord)]
      takeAx rr@ResourceRecord { rrtype = A, rdata = RD_A ipv4 } xs
        | rrname rr == ns  =  (IPv4 ipv4, rr) : xs
      takeAx rr@ResourceRecord { rrtype = AAAA, rdata = RD_AAAA ipv6 } xs
        | not disableV6NS &&
          rrname rr == ns  =  (IPv6 ipv6, rr) : xs
      takeAx _         xs  =  xs

      axList = foldr takeAx []

      refinesAx rrs = (ps, map snd ps)
        where ps = axList rrs

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
          querySection typ = lift . getSectionWithCache rankedAnswer refinesAx . fst
                             =<< resolveJustDC (succ dc) nsName typ {- resolve for not sub-level delegation. increase dc (delegation count) -}
          nsName = B8.unpack ns

      resolveAXofNS :: DNSQuery (IP, ResourceRecord)
      resolveAXofNS =
        maybe (throwDnsError DNS.IllegalDomain) pure  -- 失敗時: NS に対応する A の返答が空
        =<< liftIO . selectA =<< maybe query1Ax (pure . axList . fst) =<< lift lookupAx

  (a, _aRR) <- maybe resolveAXofNS return =<< liftIO (selectA $ axList as)
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
  getCache <- asks getCache_
  getSec <- asks currentSeconds_
  result <- liftIO $ do
    cache <- getCache
    ts <- getSec
    return $ Cache.lookup ts dom typ DNS.classIN cache
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
cacheSection rs rank = cacheRRSet
  where
    (errRRSs, rrss) = insertSetFromSection rs rank
    putRRSet putk = putk $ \key ttl crs r ->
      logLines Log.DEBUG
      [ "cacheRRSet: " ++ show ((key, ttl), r)
      , "  " ++ show crs ]
    putInvalidRRS rrs =
      logLines Log.NOTICE $
      "invalid RR set:" :
      map (("  " ++) . show) rrs
    cacheRRSet = do
      mapM_ putInvalidRRS errRRSs
      mapM_ putRRSet rrss
      insertRRSet <- asks insert_
      liftIO $ mapM_ ($ insertRRSet) rrss

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
