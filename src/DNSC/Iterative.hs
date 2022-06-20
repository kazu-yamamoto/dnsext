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
  Result,
  -- * low-level interfaces
  DNSQuery, runDNSQuery,
  replyMessage, replyResult,
  resolve, resolveJust, iterative,
  Context (..),
  normalizeName,
  ) where

-- GHC packages
import Control.Arrow ((&&&))
import Control.Monad (when, unless, join)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Control.Monad.Trans.Reader (ReaderT (..), asks)
import qualified Data.ByteString.Char8 as B8
import Data.Int (Int64)
import Data.Maybe (listToMaybe, isJust)
import Data.List (isSuffixOf, unfoldr, uncons, sortOn)
import qualified Data.Set as Set

-- other packages
import System.Random (randomR, getStdRandom)

-- dns packages
import Data.IP (IP (IPv4, IPv6))
import Network.DNS
  (Domain, ResolvConf (..), FlagOp (FlagClear), DNSError, RData (..), TTL,
   TYPE(A, NS, AAAA, CNAME, SOA), ResourceRecord (ResourceRecord, rrname, rrtype, rdata),
   RCODE, DNSHeader, DNSMessage)
import qualified Network.DNS as DNS

-- this package
import DNSC.RootServers (rootServers)
import DNSC.DNSUtil (lookupRaw)
import DNSC.Types (NE, Timestamp)
import qualified DNSC.Log as Log
import DNSC.Cache
  (Ranking (RankAdditional), rankedAnswer, rankedAuthority, rankedAdditional,
   insertSetFromSection, insertSetEmpty, Key, CRSet, Cache)
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
  (Key -> TTL -> CRSet -> Ranking -> IO (),
   IO Cache)
type TimeCache = (IO Int64, IO ShowS)

newContext :: (Log.Level -> [String] -> IO ()) -> Bool -> UpdateCache -> TimeCache
           -> IO Context
newContext putLines disableV6NS (ins, getCache) (curSec, timeStr) = do
  let cxt = Context
        { logLines_ = putLines, disableV6NS_ = disableV6NS
        , insert_ = ins, getCache_ = getCache
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
  <$> withNormalized (B8.unpack bn) getResult cxt
  where
    getResult n = do
      guardRequestHeader reqH
      replyResult n typ

{- response code, answer section, authority section -}
type Result = (RCODE, [ResourceRecord], [ResourceRecord])

-- 最終的な解決結果を得る
runResolve :: Context -> Name -> TYPE
           -> IO (Either QueryError (([ResourceRecord] -> [ResourceRecord], Domain), Either Result DNSMessage))
runResolve cxt n typ = withNormalized n (`resolve` typ) cxt

-- 権威サーバーからの解決結果を得る
runResolveJust :: Context -> Name -> TYPE -> IO (Either QueryError (DNSMessage, Delegation))
runResolveJust cxt n typ = withNormalized n (`resolveJust` typ) cxt

-- 反復後の委任情報を得る
runIterative :: Context -> Delegation -> Name -> IO (Either QueryError Delegation)
runIterative cxt sa n = withNormalized n (iterative sa) cxt

---

guardRequestHeader :: DNSHeader -> DNSQuery ()
guardRequestHeader reqH = unless rd $ throwE $ HasError DNS.Refused DNS.defaultResponse
  where
    rd = DNS.recDesired $ DNS.flags reqH

replyMessage :: Either QueryError Result
             -> DNS.Identifier -> [DNS.Question]
             -> Either String DNSMessage
replyMessage eas ident rqs =
  either queryError (Right . message) eas
  where
    dnsError de = fmap message $ (,,) <$> rcodeDNSError de <*> pure [] <*> pure []
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
      HasError rc _m  ->  Right $ message (rc, [], [])

    message (rcode, rrs, auth) =
      res
      { DNS.header = h { DNS.identifier = ident
                       , DNS.flags = f { DNS.authAnswer = False, DNS.rcode = rcode } }
      , DNS.answer = rrs
      , DNS.authority = auth
      , DNS.question = rqs
      }
    res = DNS.defaultResponse
    h = DNS.header res
    f = DNS.flags h

-- 反復検索を使って返答メッセージ用の結果コードと応答セクションを得る.
replyResult :: Name -> TYPE -> DNSQuery Result
replyResult n typ = do
  ((aRRs, _rn), etm) <- resolve n typ
  let answer msg = (DNS.rcode $ DNS.flags $ DNS.header msg, DNS.answer msg, DNS.authority msg)
      makeResult (rcode, ans, auth) = (rcode, aRRs ans, auth)
  return $ makeResult $ either id answer etm

maxCNameChain :: Int
maxCNameChain = 16

type DRRList = [ResourceRecord] -> [ResourceRecord]

{- 反復検索を使って最終的な権威サーバーからの DNSMessage を得る.
   目的の TYPE の RankAnswer 以上のキャッシュ読み出しが得られた場合はそれが結果となる.
   目的の TYPE が CNAME 以外の場合、結果が CNAME なら繰り返し解決する. その際に CNAME レコードのキャッシュ書き込みを行なう.
   目的の TYPE の結果レコードのキャッシュ書き込みは行なわない. -}
resolve :: Name -> TYPE -> DNSQuery ((DRRList, Domain), Either Result DNSMessage)
resolve n0 typ
  | typ == CNAME  =  justCNAME n0
  | otherwise     =  recCNAMEs 0 n0 id
  where
    justCNAME n = do
      let noCache = do
            (msg, _nss@(((_, nsRR), _), _)) <- resolveJust n CNAME
            lift $ cacheAnswer (rrname nsRR) bn msg
            pure ((id, bn), Right msg)

          withNXC (soa, _rank) = pure ((id, bn), Left (DNS.NameErr, [], soa))

          cachedCNAME (rrs, soa) = pure ((id, bn), Left (DNS.NoErr, rrs, soa))  {- target RR is not CNAME destination but CNAME, so NoErr -}

      maybe
        (maybe noCache withNXC =<< lift (lookupNX bn))
        (cachedCNAME . either (\soa -> ([], soa)) (\(_cn, cnRR) -> ([cnRR], [])))
        =<< lift (lookupCNAME bn)

        where
          bn = B8.pack n

    -- CNAME 以外のタイプの検索について、CNAME のラベルで検索しなおす.
    recCNAMEs :: Int -> Name -> DRRList -> DNSQuery ((DRRList, Domain), Either Result DNSMessage)
    recCNAMEs cc n aRRs
      | cc > mcc  = lift (logLn Log.NOTICE $ "query: cname chain limit exceeded: " ++ show (n0, typ))
                    *> throwDnsError DNS.ServerFailure
      | otherwise = do
      let recCNAMEs_ (cn, cnRR) = recCNAMEs (succ cc) (B8.unpack cn) (aRRs . (cnRR :))
          noCache = do
            (msg, _nss@(((_, nsRR), _), _)) <- resolveJust n typ
            cname <- lift $ getSectionWithCache rankedAnswer refinesCNAME msg
            let checkTypeRR =
                  when (any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg) $
                    throwDnsError DNS.UnexpectedRDATA  -- CNAME と目的の TYPE が同時に存在した場合はエラー
            maybe (lift $ cacheAnswer (rrname nsRR) bn msg) (const checkTypeRR) cname

            maybe (pure ((aRRs, bn), Right msg)) recCNAMEs_ cname

          withNXC (soa, _rank) = pure ((aRRs, bn), Left (DNS.NameErr, [], soa))

          noTypeCache =
            maybe
            (maybe noCache withNXC =<< lift (lookupNX bn))
            recCNAMEs_ {- recurse with cname cache -}
            =<< lift (joinE <$> lookupCNAME bn)  {- CNAME が NODATA だったときは CNAME による再検索をしないケースとして扱う -}
            where joinE = (either (const Nothing) Just =<<)

          cachedType (tyRRs, soa) = pure ((aRRs, bn), Left (DNS.NoErr, tyRRs, soa))

      maybe
        noTypeCache
        (cachedType . either (\(soa, _rank) -> ([], soa)) (\tyRRs -> (tyRRs, []))) {- return cached result with target typ -}
        =<< lift (lookupType bn typ)

        where
          mcc = maxCNameChain
          bn = B8.pack n
          refinesCNAME rrs = (fst <$> uncons ps, map snd ps)
            where ps = cnameList bn (,) rrs

    lookupNX :: Domain -> ReaderT Context IO (Maybe ([ResourceRecord], Ranking))
    lookupNX bn = maybe (return Nothing) (either (return . Just) inconsistent) =<< lookupType bn Cache.nxTYPE
      where inconsistent rrs = do
              logLn Log.NOTICE $ "resolve: inconsistent NX cache found: dom=" ++ show bn ++ ", " ++ show rrs
              return Nothing

    -- Nothing のときはキャッシュに無し
    -- Just Left のときはキャッシュに有るが CNAME レコード無し
    lookupCNAME :: Domain -> ReaderT Context IO (Maybe (Either [ResourceRecord] (Domain, ResourceRecord)))
    lookupCNAME bn = do
      maySOAorCNRRs <- lookupType bn CNAME
      return $ do
        let soa (rrs, _rank) = Just $ Left rrs
            cname rrs = Right . fst <$> uncons (cnameList bn (,) rrs)  {- empty ではないはずなのに cname が空のときはキャッシュ無しとする -}
        either soa cname =<< maySOAorCNRRs

    cacheAnswer srcDom dom msg
      | null $ DNS.answer msg  =  do
          case rcode of
            DNS.NoErr    ->  cacheEmptySection srcDom dom typ rankedAnswer msg
            DNS.NameErr  ->  cacheEmptySection srcDom dom Cache.nxTYPE rankedAnswer msg
            _            ->  return ()
      | otherwise              =  do
          getSectionWithCache rankedAnswer refinesX msg
      where
        rcode = DNS.rcode $ DNS.flags $ DNS.header msg
        refinesX rrs = ((), ps)
          where
            ps = filter isX rrs
            isX rr = rrname rr == dom && rrtype rr == typ

    lookupType bn t = (replyRank =<<) <$> lookupCacheEither bn t
    replyRank (x, rank)
      -- 最も低い ranking は reply の answer に利用しない
      -- https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1
      | rank <= RankAdditional  =  Nothing
      | otherwise               =  Just x

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

    lookupNX :: ReaderT Context IO Bool
    lookupNX = isJust <$> lookupCache name Cache.nxTYPE

    -- Nothing のときはキャッシュに無し
    -- Just Nothing のときはキャッシュに有るが委任情報無し
    lookupNS :: ReaderT Context IO (Maybe (Maybe Delegation))
    lookupNS = do
      m <- lookupCache name NS
      return $ do
        (rrs, _) <- m
        let delegation ns = (ns, [])
        Just $ delegation <$> uncons (nsList name (,) rrs)  -- キャッシュに有り

    stepQuery :: Delegation -> DNSQuery (Maybe Delegation)  -- Nothing のときは委任情報無し
    stepQuery nss_@(((_, nsRR), _), _) = do
      sa <- selectDelegation dc nss_  -- 親ドメインから同じ NS の情報が引き継がれた場合も、NS のアドレスを選択しなおすことで balancing する.
      lift $ logLn Log.INFO $ "iterative: norec: " ++ show (sa, name, A)
      msg <- norec sa name A
      lift $ delegationWithCache (rrname nsRR) name msg

    step :: Delegation -> DNSQuery (Maybe Delegation)  -- Nothing のときは委任情報無し
    step nss_ = do
      let withNXC nxc
            | nxc        =  return Nothing
            | otherwise  =  stepQuery nss_
      maybe (withNXC =<< lift lookupNX) return =<< lift lookupNS

-- 権威サーバーの返答から委任情報を取り出しつつキャッシュする
delegationWithCache :: Domain -> Domain -> DNSMessage -> ReaderT Context IO (Maybe Delegation)
delegationWithCache srcDom dom msg =
  -- 選択可能な NS が有るときだけ Just
  maybe
  (ncache *> return Nothing)
  (fmap Just . delegation)
  $ uncons nss
  where
    delegation xs = do
      cacheNS
      cacheAdds
      return (xs, adds)
    (nss, cacheNS) = getSection rankedAuthority refinesNS msg
      where refinesNS = unzip . nsList dom (\ns rr -> ((ns, rr), rr))
    (adds, cacheAdds) = getSection rankedAdditional refinesAofNS msg
      where refinesAofNS rrs = (rrs, sortOn (rrname &&& rrtype) $ filter match rrs)
            match rr = rrtype rr `elem` [A, AAAA] && rrname rr `Set.member` nsSet
            nsSet = Set.fromList $ map fst nss

    ncache
      | rcode == DNS.NoErr    =  cacheEmptySection srcDom dom NS rankedAuthority msg
      | rcode == DNS.NameErr  =
        if hasCNAME then      do cacheCNAME
                                 cacheEmptySection srcDom dom NS rankedAuthority msg
        else                     cacheEmptySection srcDom dom Cache.nxTYPE rankedAuthority msg
      | otherwise             =  pure ()
      where rcode = DNS.rcode $ DNS.flags $ DNS.header msg
    (hasCNAME, cacheCNAME) = getSection rankedAnswer refinesCNAME msg
      where refinesCNAME rrs = (not $ null cns, crrs)
            {- CNAME 先の NX をキャッシュしたいならここで返す.
               しかしCNAME 先の NS に問い合わせないと返答で使える rank のレコードは得られない. -}
              where (cns, crrs) = unzip $ cnameList dom (,) rrs

nsList :: Domain -> (Domain ->  ResourceRecord -> a)
       -> [ResourceRecord] -> [a]
nsList dom h = foldr takeNS []
  where
    takeNS rr@ResourceRecord { rrtype = NS, rdata = RD_NS ns } xs
      | rrname rr == dom  =  h ns rr : xs
    takeNS _         xs   =  xs

cnameList :: Domain -> (Domain -> ResourceRecord -> a)
          -> [ResourceRecord] -> [a]
cnameList dom h = foldr takeCNAME []
  where
    takeCNAME rr@ResourceRecord { rrtype = CNAME, rdata = RD_CNAME cn } xs
      | rrname rr == dom  =  h cn rr : xs
    takeCNAME _      xs   =  xs

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

-- | when cache has EMPTY result, lookup SOA data for top domain of this zone
lookupCacheEither :: Domain -> TYPE
                  -> ReaderT Context IO (Maybe (Either ([ResourceRecord], Ranking) [ResourceRecord], Ranking))
lookupCacheEither dom typ = do
  getCache <- asks getCache_
  getSec <- asks currentSeconds_
  result <- liftIO $ do
    cache <- getCache
    ts <- getSec
    return $ Cache.lookupEither ts dom typ DNS.classIN cache
  logLn Log.DEBUG $ "lookupCacheEither: " ++ unwords [show dom, show typ, show DNS.classIN, ":",
                                                      maybe "miss" (\ (_, rank) -> "hit: " ++ show rank) result]
  return result

getSection :: (m -> ([ResourceRecord], Ranking))
           -> ([ResourceRecord] -> (a, [ResourceRecord]))
           -> m -> (a, ReaderT Context IO ())
getSection getRanked refines msg =
  withSection $ getRanked msg
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

-- | The `cacheEmptySection srcDom dom typ getRanked msg` caches two pieces of information from `msg`.
--   One is that the data for `dom` and `typ` are empty, and the other is the SOA record for the zone of `srcDom`.
--   The `getRanked` function returns the section with the empty information.
cacheEmptySection :: Domain -> Domain -> TYPE
                  -> (DNSMessage -> ([ResourceRecord], Ranking))
                  -> DNSMessage -> ReaderT Context IO ()
cacheEmptySection srcDom dom typ getRanked msg =
  either ncWarn doCache takeNCTTL
  where
    doCache ncttl = do
      cacheSOA
      cacheEmpty srcDom dom typ ncttl rank
    (_section, rank) = getRanked msg
    (takeNCTTL, cacheSOA) = getSection rankedAuthority refinesSOA msg
      where
        refinesSOA srrs = (single ttls, take 1 rrs)  where (ttls, rrs) = unzip $ foldr takeSOA [] srrs
        takeSOA rr@ResourceRecord { rrtype = SOA, rdata = RD_SOA mname mail ser refresh retry expire ncttl } xs
          | rrname rr == srcDom  =  (fromSOA mname mail ser refresh retry expire ncttl rr, rr) : xs
          | otherwise            =  xs
        takeSOA _         xs     =  xs
        {- the minimum of the SOA.MINIMUM field and SOA's TTL
            https://datatracker.ietf.org/doc/html/rfc2308#section-3
            https://datatracker.ietf.org/doc/html/rfc2308#section-5 -}
        fromSOA _ _ _ _ _ _ ncttl rr = minimum [ncttl, DNS.rrttl rr, maxNCacheTTL]
        maxNCacheTTL = 21600
        single list = case list of
          []    ->  Left "no SOA records found"
          [x]   ->  Right x
          _:_:_ ->  Left "multiple SOA records found"
    ncWarn s
      | not $ null answer  =  logLines Log.DEBUG $
                              [ "cacheEmptySection: from-domain=" ++ show srcDom ++ ", domain=" ++ show dom ++ ": " ++ s
                              , "  because of non empty answers:"
                              ] ++
                              map (("  " ++) . show) answer
      | otherwise          =  logLn Log.NOTICE $ "cacheEmptySection: from-domain=" ++ show srcDom ++ ", domain=" ++ show dom ++ ": " ++ s
      where answer = DNS.answer msg

cacheEmpty :: Domain -> Domain -> TYPE -> TTL -> Ranking -> ReaderT Context IO ()
cacheEmpty srcDom dom typ ttl rank = do
  logLn Log.DEBUG $ "cacheEmpty: " ++ show (srcDom, dom, typ, ttl, rank)
  insertRRSet <- asks insert_
  liftIO $ insertSetEmpty srcDom dom typ ttl rank insertRRSet

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
