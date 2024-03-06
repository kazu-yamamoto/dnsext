{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Cache (
    lookupValid,
    LookupResult,
    foldLookupResult,
    lookupRRsetEither,
    lookupCache,
    cacheRcodeWithOrigQ,
    failWithCacheOrigQ,
    cacheAnswer,
    cacheSection,
    cacheNoRRSIG,
    cacheNoDelegation,
) where

-- GHC packages

-- other packages

-- dnsext packages
import qualified DNS.Log as Log
import DNS.RRCache (
    Ranking,
    cpsInsertNegative,
    cpsInsertNegativeNoSOA,
    rankedAnswer,
    rankedAuthority,
 )
import qualified DNS.RRCache as Cache
import DNS.SEC
import qualified DNS.SEC.Verify as SEC
import DNS.Types
import qualified DNS.Types as DNS
import System.Console.ANSI.Types

-- this package
import DNS.Iterative.Imports hiding (insert)
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
import qualified DNS.Iterative.Query.Verify as Verify

---- import for doctest
import DNS.Iterative.Query.TestEnv

type CacheHandler a = EpochTime -> Domain -> TYPE -> CLASS -> Cache.Cache -> Maybe (a, Ranking)

withLookupCache :: CacheHandler a -> String -> Domain -> TYPE -> ContextT IO (Maybe (a, Ranking))
withLookupCache h logMark dom typ = do
    cache <- liftIO =<< asks getCache_
    ts <- liftIO =<< asks currentSeconds_
    let result = h ts dom typ DNS.IN cache
    logLn Log.DEBUG $
        let pprResult = maybe "miss" (\(_, rank) -> "hit: " ++ show rank) result
            mark ws
                | null logMark = ws
                | otherwise = (logMark ++ ":") : ws
         in unwords $ "lookupCache:" : mark [show dom, show typ, show DNS.IN, ":", pprResult]
    return result

lookupRRset :: String -> Domain -> TYPE -> ContextT IO (Maybe (RRset, Ranking))
lookupRRset logMark dom typ = withLookupCache mkAlive logMark dom typ
  where
    mkAlive :: CacheHandler RRset
    mkAlive ts = Cache.lookupAlive ts result
    result ttl crs rank = (,) <$> Cache.foldHit (const Nothing) (const Nothing) (Just . positive) crs <*> pure rank
      where
        positive = Cache.positiveHit notVerified valid
        notVerified = notVerifiedRRset dom typ DNS.IN ttl
        valid = validRRset dom typ DNS.IN ttl

guardValid :: Maybe (RRset, Ranking) -> Maybe (RRset, Ranking)
guardValid m = do
    (rrset, _rank) <- m
    guard $ rrsetValid rrset
    m

lookupValid :: Domain -> TYPE -> ContextT IO (Maybe (RRset, Ranking))
lookupValid dom typ = guardValid <$> lookupRRset "" dom typ

{- FOURMOLU_DISABLE -}
data LookupResult
    = LKNegative RRset Ranking
    | LKNegativeNoSOA RCODE
    | LKPositive RRset
    deriving Show

foldLookupResult :: (RRset -> Ranking -> a) -> (RCODE -> a) -> (RRset -> a) -> LookupResult -> a
foldLookupResult negative nsoa positive lkre = case lkre of
    LKNegative rrset rank  -> negative rrset rank
    LKNegativeNoSOA rcode  -> nsoa rcode
    LKPositive rrset       -> positive rrset
{- FOURMOLU_ENABLE -}

-- | when cache has EMPTY result, lookup SOA data for top domain of this zone
lookupRRsetEither :: String -> Domain -> TYPE -> ContextT IO (Maybe (LookupResult, Ranking))
lookupRRsetEither logMark dom typ = withLookupCache mkAlive logMark dom typ
  where
    mkAlive :: CacheHandler LookupResult
    mkAlive now dom_ typ_ cls cache = Cache.lookupAlive now (result now cache) dom_ typ_ cls cache
    result now cache ttl crs rank = (,) <$> hit <*> pure rank
      where
        hit = Cache.foldHit negative negativeNoSOA positive crs
        {- EMPTY hit. empty ranking and SOA result. -}
        negative soaDom = Cache.lookupAlive now (soaResult ttl soaDom) soaDom SOA DNS.IN cache
        negativeNoSOA = Just . LKNegativeNoSOA
        positive = Just . LKPositive . Cache.positiveHit notVerified valid
        notVerified rds = notVerifiedRRset dom typ DNS.IN ttl rds
        valid rds sigs = validRRset dom typ DNS.IN ttl rds sigs

    soaResult ettl srcDom ttl crs rank = LKNegative <$> Cache.foldHit (const Nothing) (const Nothing) (Just . positive) crs <*> pure rank
      where
        positive = Cache.positiveHit notVerified valid
        notVerified = notVerifiedRRset srcDom SOA DNS.IN (ettl `min` ttl {- treated as TTL of empty data -})
        valid = validRRset srcDom SOA DNS.IN (ettl `min` ttl {- treated as TTL of empty data -})

notVerifiedRRset :: Domain -> TYPE -> CLASS -> TTL -> [RData] -> RRset
notVerifiedRRset dom typ cls ttl rds = RRset dom typ cls ttl rds NotVerifiedRRS

validRRset :: Domain -> TYPE -> CLASS -> TTL -> [RData] -> [RD_RRSIG] -> RRset
validRRset dom typ cls ttl rds sigs = RRset dom typ cls ttl rds (ValidRRS sigs)

---

-- $setup
-- >>> :set -XOverloadedStrings

_newTestEnv :: IO Env
_newTestEnv = newTestEnv (const $ pure ()) False 2048

-- | lookup RRs without sigs. empty RR list result for negative case.
--
-- >>> env <- _newTestEnv
-- >>> cxtIN = queryContextIN "pqr.example.com." A mempty
-- >>> runCxt c = runReaderT (runReaderT c env) cxtIN
-- >>> pos1 = cacheNoRRSIG [ResourceRecord "p2.example.com." A IN 7200 $ rd_a "10.0.0.3"] Cache.RankAnswer *> lookupCache "p2.example.com." A
-- >>> fmap (map rdata . fst) <$> runCxt pos1
-- Just [10.0.0.3]
-- >>> nodata1 = cacheNegative "example.com." "nodata1.example.com." A 7200 Cache.RankAnswer *> lookupCache "nodata1.example.com." A
-- >>> fmap fst <$> runCxt nodata1
-- Just []
-- >>> nodata2 = cacheNegativeNoSOA NoErr "nodata2.example.com." A 7200 Cache.RankAnswer *> lookupCache "nodata2.example.com." A
-- >>> fmap fst <$> runCxt nodata2
-- Just []
-- >>> err1 = cacheNegative "example.com." "err1.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupCache "err1.example.com." Cache.ERR
-- >>> fmap fst <$> runCxt err1
-- Just []
-- >>> err2 = cacheNegativeNoSOA ServFail "err2.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupCache "err2.example.com." Cache.ERR
-- >>> fmap fst <$> runCxt err2
-- Just []
-- >>> err3 = cacheNegativeNoSOA Refused "err3.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupCache "err3.example.com." Cache.ERR
-- >>> fmap fst <$> runCxt err3
-- Just []
lookupCache :: Domain -> TYPE -> ContextT IO (Maybe ([ResourceRecord], Ranking))
lookupCache dom typ = withLookupCache mkAlive "" dom typ
  where
    mkAlive :: CacheHandler [ResourceRecord]
    mkAlive now = Cache.lookupAlive now result
    result ttl crs rank = Just (Cache.unCRSet (const []) (const []) mapRR (\rds _sigs -> mapRR rds) crs, rank)
      where
        mapRR = map $ ResourceRecord dom typ DNS.IN ttl

cacheNoRRSIG :: [ResourceRecord] -> Ranking -> ContextT IO ()
cacheNoRRSIG rrs0 rank = do
    either crrsError insert $ SEC.canonicalRRsetSorted sortedRRs
  where
    prefix = ("cacheNoRRSIG: " ++)
    plogLn lv s = logLn lv $ prefix s
    crrsError _ =
        logLines Log.WARN $ prefix "no caching RR set:" : map (("\t" ++) . show) rrs0
    insert hrrs = do
        insertRRSet <- asks insert_
        hrrs $ \dom typ cls ttl rds -> do
            plogLn Log.DEBUG $ unwords ["RRset:", show (((dom, typ, cls), ttl), rank), ' ' : show rds]
            liftIO $ Cache.notVerified rds (pure ()) $ \crs -> insertRRSet (DNS.Question dom typ cls) ttl crs rank
    (_, sortedRRs) = unzip $ SEC.sortRDataCanonical rrs0

cacheSection :: [ResourceRecord] -> Ranking -> ContextT IO ()
cacheSection rs rank = mapM_ (`cacheNoRRSIG` rank) $ rrsList rs
  where
    rrsKey rr = (rrname rr, rrtype rr, rrclass rr)
    rrsList = groupBy ((==) `on` rrsKey) . sortOn rrsKey {- handled null case, no group -}

-- | The `cacheSectionNegative zone dom typ getRanked msg` caches two pieces of information from `msg`.
--   One is that the data for `dom` and `typ` are empty, and the other is the SOA record for the zone of
--   the sub-domains under `zone`.
--   The `getRanked` function returns the section with the empty information.
{- FOURMOLU_DISABLE -}
cacheSectionNegative
    :: Domain -> [RD_DNSKEY]
    -> Domain -> TYPE
    -> (DNSMessage -> ([ResourceRecord], Ranking)) -> DNSMessage
    -> [RRset]
    -> ContextT IO [RRset] {- returns verified authority section -}
{- FOURMOLU_ENABLE -}
cacheSectionNegative zone dnskeys dom typ getRanked msg nws = do
    getSec <- asks currentSeconds_
    Verify.cases getSec zone dnskeys rankedAuthority msg zone SOA fromSOA nullSOA ($> []) $ \ps soaRRset cacheSOA -> do
        let doCache (soaDom, ncttl) = do
                cacheSOA
                withSection getRanked msg $ \_rrs rank -> cacheNegative soaDom dom typ ncttl rank
        either (ncWarn >>> ($> [])) (doCache >>> ($> soaRRset : nws)) $ single ps
  where
    fromSOA :: ResourceRecord -> Maybe (Domain, TTL)
    fromSOA ResourceRecord{..} = (,) rrname . soaTTL <$> DNS.fromRData rdata
      where
        {- the minimum of the SOA.MINIMUM field and SOA's TTL
           https://datatracker.ietf.org/doc/html/rfc2308#section-3
           https://datatracker.ietf.org/doc/html/rfc2308#section-5 -}
        soaTTL soa = minimum [DNS.soa_minimum soa, rrttl, maxNCacheTTL]
        maxNCacheTTL = 21600
    nullSOA = withSection getRanked msg $ \_rrs rank -> cacheNegativeNoSOA (rcode msg) dom typ defaultTTL rank $> []
      where
        defaultTTL = 1800

    single xs = case xs of
        [] -> Left "no SOA records found"
        [x] -> Right x
        _ : _ : _ -> Left "multiple SOA records found"
    ncWarn s
        | not $ null answer = do
            plogLines Log.DEBUG $ map ("\t" ++) ("because of non empty answers:" : map show answer)
        | null soas = do
            plogLines Log.WARN $ ["\tno SOA records in authority section"]
        | otherwise = do
            plogLines Log.WARN $ map ("\t" ++) (("SOA records in authority section:" :) $ map show soas)
      where
        withCtx ws = [s ++ ","] ++ ws ++ ["zone " ++ show zone ++ ":"]
        showQ' qmark name ty = qmark ++ " " ++ show name ++ " " ++ show ty ++ ","
        showQ _qmark [] = []
        showQ qmark ((Question name ty _) : _) = [showQ' qmark name ty]
        plogLines lv xs = do
            let key = [showQ' "key" dom typ]
                query = showQ "query" (question msg)
            orig <- (\q -> showQ "orig-query" [q]) <$> lift (asks origQuestion_)
            logLines lv $ ("cacheSectionNegative: " ++ unwords (withCtx $ key ++ query ++ orig)) : xs
        answer = DNS.answer msg
        soas = filter ((== SOA) . rrtype) $ DNS.authority msg

cacheNegative :: Domain -> Domain -> TYPE -> TTL -> Ranking -> ContextT IO ()
cacheNegative zone dom typ ttl rank = do
    logLn Log.DEBUG $ "cacheNegative: " ++ show (zone, dom, typ, ttl, rank)
    insertRRSet <- asks insert_
    liftIO $ cpsInsertNegative zone dom typ ttl rank insertRRSet

cacheNegativeNoSOA :: RCODE -> Domain -> TYPE -> TTL -> Ranking -> ContextT IO ()
cacheNegativeNoSOA rc dom typ ttl rank = do
    logLn Log.DEBUG $ "cacheNegativeNoSOA: " ++ show (rc, dom, typ, ttl, rank)
    insertRRSet <- asks insert_
    liftIO $ cpsInsertNegativeNoSOA rc dom typ ttl rank insertRRSet

cacheRcodeWithOrigQ :: RCODE -> Ranking -> ContextT IO ()
cacheRcodeWithOrigQ rcode rank = do
    let defaultTTL = 1800
    Question dom typ _ <- lift $ asks origQuestion_
    cacheNegativeNoSOA rcode dom typ defaultTTL rank

{- FOURMOLU_DISABLE -}
failWithCacheOrigQ :: Ranking -> DNSError -> DNSQuery a
failWithCacheOrigQ rank e = do
    lift $ runErrorRC (pure ()) (`cacheRcodeWithOrigQ` rank)
    throwDnsError e
  where
    runErrorRC n j = case e of
             FormatError       -> j DNS.FormatErr
             ServerFailure     -> j DNS.ServFail
             OperationRefused  -> j DNS.Refused
             IllegalDomain     -> j DNS.ServFail
             _                 -> n
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
cacheAnswer :: Delegation -> Domain -> TYPE -> DNSMessage -> DNSQuery ([RRset], [RRset])
cacheAnswer d@Delegation{..} dom typ msg = do
    getSec <- lift $ asks currentSeconds_
    (result, cacheX) <- verify getSec
    lift cacheX
    return result
  where
    qinfo = show dom ++ " " ++ show typ
    verify getSec = Verify.cases getSec zone dnskeys rankedAnswer msg dom typ Just nullX ncX $ \_ xRRset cacheX -> do
        nws <- witnessWildcardExpansion
        let (~verifyMsg, ~verifyColor, raiseOnVerifyFailure)
                | FilledDS [] <- delegationDS = ("no verification - no DS, " ++ qinfo, Just Yellow, pure ())
                | rrsetValid xRRset = ("verification success - RRSIG of " ++ qinfo, Just Green, pure ())
                | NotFilledDS o <- delegationDS = ("not consumed not-filled DS: case=" ++ show o ++ ", " ++ qinfo, Nothing, pure ())
                | otherwise = ("verification failed - RRSIG of " ++ qinfo, Just Red, throwDnsError DNS.ServerFailure)
        lift $ clogLn Log.DEMO verifyColor verifyMsg
        raiseOnVerifyFailure
        pure (([xRRset], nws), cacheX)
      where
        witnessWildcardExpansion = wildcardWitnessAction d dom typ msg

    nullX = doCacheEmpty <&> \e -> (([], e), pure ())
    doCacheEmpty = case rcode of
        {- authority sections for null answer -}
        DNS.NoErr      -> lift . cacheSectionNegative zone dnskeys dom typ       rankedAnswer msg =<< witnessNoDatas
        DNS.NameErr    -> lift . cacheSectionNegative zone dnskeys dom Cache.ERR rankedAnswer msg =<< witnessNameErr
        _ | crc rcode  -> lift $ cacheSectionNegative zone dnskeys dom typ       rankedAnswer msg []
          | otherwise  -> pure []
      where
        crc rc = rc `elem` [DNS.FormatErr, DNS.ServFail, DNS.Refused]
        nullK = nsecFailed $ "no NSEC/NSEC3 for NameErr/NoData: " ++ qinfo
        (witnessNoDatas, witnessNameErr) = negativeWitnessActions nullK d dom typ msg

    ncX _ncLog = pure (([], []), pure ())

    rcode = DNS.rcode msg
    zone = delegationZone
    dnskeys = delegationDNSKEY
{- FOURMOLU_ENABLE -}

cacheNoDelegation :: Delegation -> Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> DNSQuery ()
cacheNoDelegation d zone dnskeys dom msg
    | rcode == DNS.NoErr = cacheNoDataNS $> ()
    | rcode == DNS.NameErr = nameErrors $> ()
    | otherwise = pure ()
  where
    nameErrors = lift (asks currentSeconds_) >>=
        \getSec -> Verify.cases getSec zone dnskeys rankedAnswer msg dom CNAME cnRD nullCNAME ncCNAME $
        \_rds _cnRRset cacheCNAME -> lift cacheCNAME *> cacheNoDataNS
    {- If you want to cache the NXDOMAIN of the CNAME destination, return it here.
       However, without querying the NS of the CNAME destination,
       you cannot obtain the record of rank that can be used for the reply. -}
    cnRD rr = DNS.fromRData $ rdata rr :: Maybe DNS.RD_CNAME
    nullCNAME = lift . cacheSectionNegative zone dnskeys dom Cache.ERR rankedAuthority msg =<< witnessNameErr
    ncCNAME _ncLog = cacheNoDataNS
    {- not always possible to obtain NoData witness for NS
       * no NSEC/NSEC3 records - ex. A record exists
       * encloser NSEC/NSEC3 records for other than QNAME - ex. dig @ns1.dns-oarc.net. porttest.dns-oarc.net. A +dnssec -}
    cacheNoDataNS = lift $ cacheSectionNegative zone dnskeys dom NS rankedAuthority msg []
    (_witnessNoDatas, witnessNameErr) = negativeWitnessActions (pure []) d dom A msg
    rcode = DNS.rcode msg

{- FOURMOLU_DISABLE -}
wildcardWitnessAction :: Delegation -> Domain -> TYPE -> DNSMessage -> ExceptT QueryError (ContextT IO) [RRset]
wildcardWitnessAction Delegation{..} qname qtype msg = witnessWildcardExpansion
  where
    witnessWildcardExpansion
        | noDS          = pure []
        | otherwise     = Verify.getWildcardExpansion zone dnskeys rankedAuthority msg qname
                          nullK invalidK (noWitnessK "WildcardExpansion")
                          resultK resultK
    nullK = pure []
    invalidK s = failed $ "NSEC/NSEC3 WildcardExpansion: " ++ qinfo ++ " :\n" ++ s
    noWitnessK wn s = failed $ "cannot find " ++ wn ++ " witness: " ++ qinfo ++ " : " ++ s
    resultK w rrsets _ = lift $ success w $> rrsets
    success w = clogLn Log.DEMO (Just Green) $ "nsec verification success - " ++ SEC.witnessName w ++ ": " ++ qinfo
    failed = nsecFailed
    qinfo = show qname ++ " " ++ show qtype

    zone = delegationZone
    dnskeys = delegationDNSKEY
    noDS = case delegationDS of
        FilledDS [] -> True
        _           -> False
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
negativeWitnessActions :: DNSQuery [RRset] -> Delegation -> Domain -> TYPE -> DNSMessage -> (DNSQuery [RRset], DNSQuery [RRset])
negativeWitnessActions nullK Delegation{..} qname qtype msg = (witnessNoData, witnessNameError)
  where
    witnessNoData
        | noDS          = pure []
        | otherwise     = Verify.getNoDatas   zone dnskeys rankedAuthority msg qname qtype
                          nullK invalidK (noWitnessK "NoData")
                          resultK resultK resultK resultK
    witnessNameError
        | noDS          = pure []
        | otherwise     = Verify.getNameError zone dnskeys rankedAuthority msg qname
                          nullK invalidK (noWitnessK "NameError")
                          resultK resultK
    invalidK s = failed $ "NSEC/NSEC3 NameErr/NoData: " ++ qinfo ++ " :\n" ++ s
    noWitnessK wn s = failed $ "cannot find " ++ wn ++ " witness: " ++ qinfo ++ " : " ++ s
    resultK w rrsets _ = lift $ success w $> rrsets
    success w = clogLn Log.DEMO (Just Green) $ "nsec verification success - " ++ SEC.witnessName w ++ ": " ++ qinfo
    failed = nsecFailed
    ~qinfo = show qname ++ " " ++ show qtype

    zone = delegationZone
    dnskeys = delegationDNSKEY
    noDS = case delegationDS of
        FilledDS [] -> True
        _           -> False
{- FOURMOLU_ENABLE -}

nsecFailed :: String -> DNSQuery a
nsecFailed s = lift (clogLn Log.DEMO (Just Red) $ "nsec verification failed - " ++ s) *> throwDnsError DNS.ServerFailure
