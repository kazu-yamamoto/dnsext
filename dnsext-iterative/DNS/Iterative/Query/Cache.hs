{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Cache (
    lookupValid,
    LookupResult,
    foldLookupResult,
    lookupRRsetEither,
    lookupRR,
    lookupErrorRCODE,
    cacheDNSError,
    cacheNoData,
    failWithCache,
    failWithCacheOrigName,
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
import DNS.Iterative.Query.WitnessInfo

---- import for doctest
import DNS.Iterative.Query.TestEnv

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> :seti -XFlexibleContexts

_newTestEnv :: IO Env
_newTestEnv = newTestEnv (const $ pure ()) False 2048

type CacheHandler a = EpochTime -> Domain -> TYPE -> CLASS -> Cache.Cache -> Maybe (a, Ranking)

withLookupCache :: (MonadIO m, MonadReader Env m) => CacheHandler a -> String -> Domain -> TYPE -> m (Maybe (a, Ranking))
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

{- FOURMOLU_DISABLE -}
handleHits :: (TTL -> Domain -> Maybe a)
           -> (TTL -> RCODE -> Maybe a)
           -> (TTL -> [RData] -> Maybe a)
           -> (TTL -> [RData] -> Maybe a)
           -> (TTL -> [RData] -> [RD_RRSIG] -> Maybe a)
           -> CacheHandler a
handleHits soah nsoah nsh cdh vh now = Cache.lookupAlive now result
  where
    result ttl crs rank = (,) <$> Cache.hitCases (soah ttl) (nsoah ttl) (nsh ttl) (cdh ttl) (vh ttl) crs <*> pure rank
{- FOURMOLU_ENABLE -}

-- | lookup RRs without sigs. empty RR list result for negative case.
--
-- >>> env <- _newTestEnv
-- >>> runCxt c = runReaderT (runReaderT c env) $ queryContextIN "pqr.example.com." A mempty
-- >>> pos1 = cacheNoRRSIG [ResourceRecord "p2.example.com." A IN 7200 $ rd_a "10.0.0.3"] Cache.RankAnswer *> lookupRR "p2.example.com." A
-- >>> fmap (map rdata . fst) <$> runCxt pos1
-- Just [10.0.0.3]
-- >>> nodata1 = cacheNegative "example.com." "nodata1.example.com." A 7200 Cache.RankAnswer *> lookupRR "nodata1.example.com." A
-- >>> fmap fst <$> runCxt nodata1
-- Just []
-- >>> nodata2 = cacheNegativeNoSOA NoErr "nodata2.example.com." A 7200 Cache.RankAnswer *> lookupRR "nodata2.example.com." A
-- >>> fmap fst <$> runCxt nodata2
-- Just []
-- >>> err1 = cacheNegative "example.com." "err1.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupRR "err1.example.com." Cache.ERR
-- >>> fmap fst <$> runCxt err1
-- Just []
-- >>> err2 = cacheNegativeNoSOA ServFail "err2.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupRR "err2.example.com." Cache.ERR
-- >>> fmap fst <$> runCxt err2
-- Just []
-- >>> err3 = cacheNegativeNoSOA Refused "err3.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupRR "err3.example.com." Cache.ERR
-- >>> fmap fst <$> runCxt err3
-- Just []
lookupRR :: (MonadIO m, MonadReader Env m) => Domain -> TYPE -> m (Maybe ([ResourceRecord], Ranking))
lookupRR dom typ = withLookupCache h "" dom typ
  where
    h = handleHits (\_ _ -> Just []) (\_ _ -> Just []) mapRR mapRR (\ttl rds _sigs -> mapRR ttl rds)
    mapRR ttl = Just . map (ResourceRecord dom typ DNS.IN ttl)

lookupErrorRCODE :: (MonadIO m, MonadReader Env m) => Domain -> m (Maybe (RCODE, Ranking))
lookupErrorRCODE dom = withLookupCache h "" dom Cache.ERR
    where
      h = handleHits (\_ _ -> Just NameErr) (\_ -> Just) (\_ _ -> Nothing) (\_ _ -> Nothing) (\_ _ _ -> Nothing)

-- |
--
-- >>> env <- _newTestEnv
-- >>> runCxt c = runReaderT (runReaderT c env) $ queryContextIN "pqr.example.com." A mempty
-- >>> ards = [rd_a "10.0.0.3", rd_a "10.0.0.4"]
-- >>> pos1 = cacheNoRRSIG [ResourceRecord "p1.example.com." A IN 7200 rd | rd <- ards] Cache.RankAnswer *> lookupRRset "test" "p1.example.com." A
-- >>> fmap (rrsRDatas . fst) <$> runCxt pos1
-- Just [10.0.0.3,10.0.0.4]
-- >>> nodata1 = cacheNegative "example.com." "nodata1.example.com." A 7200 Cache.RankAnswer *> lookupRRset "test" "nodata1.example.com." A
-- >>> runCxt nodata1
-- Nothing
lookupRRset :: (MonadIO m, MonadReader Env m) => String -> Domain -> TYPE -> m (Maybe (RRset, Ranking))
lookupRRset logMark dom typ =
    withLookupCache (handleHits (\_ _ -> Nothing) (\_ _ -> Nothing) noSig checkDisabled valid) logMark dom typ
  where
    noSig ttl rds = Just (noSigRRset dom typ DNS.IN ttl rds)
    checkDisabled ttl rds = Just (checkDisabledRRset dom typ DNS.IN ttl rds)
    valid ttl rds sigs = Just (validRRset dom typ DNS.IN ttl rds sigs)

guardValid :: Maybe (RRset, Ranking) -> Maybe (RRset, Ranking)
guardValid m = do
    (rrset, _rank) <- m
    guard $ rrsetValid rrset
    m

lookupValid :: (MonadIO m, MonadReader Env m) => Domain -> TYPE -> m (Maybe (RRset, Ranking))
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
--
-- >>> env <- _newTestEnv
-- >>> runCxt c = runReaderT (runReaderT c env) $ queryContextIN "pqr.example.com." A mempty
-- >>> ards = [rd_a "10.0.0.3", rd_a "10.0.0.4"]
-- >>> pos1 = cacheNoRRSIG [ResourceRecord "p0.example.com." A IN 7200 rd | rd <- ards] Cache.RankAnswer *> lookupRRsetEither "test" "p0.example.com." A
-- >>> fmap (foldLookupResult (\_ _ -> "neg-soa") (\_ -> "neg-no-soa") (show . rrsRDatas) . fst) <$> runCxt pos1
-- Just "[10.0.0.3,10.0.0.4]"
-- >>> soa = cacheNoRRSIG [ResourceRecord "example.com." SOA IN 7200 $ rd_soa "ns1.example.com." "root@example.com." 2024061601 3600 900 604800 900] Cache.RankAuthAnswer
-- >>> getSOA = foldLookupResult (\rrset _ -> show $ rrsType rrset) (\_ -> "neg-no-soa") (\_ -> "pos-rrset")
-- >>> getRC = foldLookupResult (\_ _ -> "neg-soa") (\rc -> show rc) (\_ -> "pos-rrset")
-- >>> nodata1 = cacheNegative "example.com." "nodata1.example.com." A 7200 Cache.RankAnswer *> lookupRRsetEither "test" "nodata1.example.com." A
-- >>> fmap (getSOA . fst) <$> runCxt (soa *> nodata1)
-- Just "SOA"
-- >>> nodata2 = cacheNegativeNoSOA NoErr "nodata2.example.com." A 7200 Cache.RankAnswer *> lookupRRsetEither "test" "nodata2.example.com." A
-- >>> fmap (getRC . fst) <$> runCxt nodata2
-- Just "NoError"
-- >>> err1 = cacheNegative "example.com." "err1.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupRRsetEither "test" "err1.example.com." Cache.ERR
-- >>> fmap (getSOA . fst) <$> runCxt (soa *> err1)
-- Just "SOA"
-- >>> err2 = cacheNegativeNoSOA ServFail "err2.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupRRsetEither "test" "err2.example.com." Cache.ERR
-- >>> fmap (getRC . fst) <$> runCxt err2
-- Just "ServFail"
-- >>> err3 = cacheNegativeNoSOA Refused "err3.example.com." Cache.ERR 7200 Cache.RankAnswer *> lookupRRsetEither "test" "err3.example.com." Cache.ERR
-- >>> fmap (getRC . fst) <$> runCxt err3
-- Just "Refused"
lookupRRsetEither :: (MonadIO m, MonadReader Env m)
                  => String -> Domain -> TYPE -> m (Maybe (LookupResult, Ranking))
lookupRRsetEither logMark dom typ = withLookupCache h logMark dom typ
  where
    h now dom_ typ_ cls cache = handleHits negative negativeNoSOA noSig checkDisabled valid now dom_ typ_ cls cache
      where
        {- negative hit. ranking for empty-data and SOA result. -}
        negative ttl soaDom = Cache.lookupAlive now (soaResult ttl soaDom) soaDom SOA DNS.IN cache
        negativeNoSOA _ttl = Just . LKNegativeNoSOA
        noSig ttl = Just . LKPositive . noSigRRset dom typ DNS.IN ttl
        checkDisabled ttl = Just . LKPositive . checkDisabledRRset dom typ DNS.IN ttl
        valid ttl rds = Just . LKPositive . validRRset dom typ DNS.IN ttl rds

    soaResult ettl srcDom sttl crs rank = LKNegative <$> Cache.hitCases1 (const Nothing) (Just . positive) crs <*> pure rank
      where
        positive = Cache.positiveCases noSig checkDisabled valid
        noSig = noSigRRset srcDom SOA DNS.IN ttl
        checkDisabled = checkDisabledRRset dom typ DNS.IN ttl
        valid = validRRset srcDom SOA DNS.IN ttl
        ttl = ettl `min` sttl {- minimum ttl of empty-data and soa -}

noSigRRset :: Domain -> TYPE -> CLASS -> TTL -> [RData] -> RRset
noSigRRset dom typ cls ttl rds = RRset dom typ cls ttl rds notValidNoSig

checkDisabledRRset :: Domain -> TYPE -> CLASS -> TTL -> [RData] -> RRset
checkDisabledRRset dom typ cls ttl rds = RRset dom typ cls ttl rds notValidCheckDisabled

validRRset :: Domain -> TYPE -> CLASS -> TTL -> [RData] -> [RD_RRSIG] -> RRset
validRRset dom typ cls ttl rds sigs = RRset dom typ cls ttl rds (ValidRRS sigs)

---

cacheNoRRSIG :: (MonadIO m, MonadReader Env m) => [ResourceRecord] -> Ranking -> m ()
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
            liftIO $ Cache.noSig rds (pure ()) $ \crs -> insertRRSet (DNS.Question dom typ cls) ttl crs rank
    (_, sortedRRs) = unzip $ SEC.sortRDataCanonical rrs0

cacheSection :: (MonadIO m, MonadReader Env m) => [ResourceRecord] -> Ranking -> m ()
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
    :: (MonadIO m, MonadReader Env m, MonadReaderQC m)
    => Domain -> [RD_DNSKEY]
    -> Domain -> TYPE
    -> (DNSMessage -> ([ResourceRecord], Ranking)) -> DNSMessage
    -> [RRset]
    -> m [RRset] {- returns verified authority section -}
{- FOURMOLU_ENABLE -}
cacheSectionNegative zone dnskeys dom typ getRanked msg nws = do
    maxNegativeTTL <- asks maxNegativeTTL_
    getSec <- asks currentSeconds_
    let {- the minimum of the SOA.MINIMUM field and SOA's TTL
           https://datatracker.ietf.org/doc/html/rfc2308#section-3
           https://datatracker.ietf.org/doc/html/rfc2308#section-5 -}
        soaTTL ttl soa = minimum [DNS.soa_minimum soa, ttl, maxNegativeTTL]
        fromSOA ResourceRecord{..} = (,) rrname . soaTTL rrttl <$> DNS.fromRData rdata
        cacheNoSOA _rrs rank = cacheNegativeNoSOA (rcode msg) dom typ maxNegativeTTL rank $> []
        nullSOA = withSection getRanked msg cacheNoSOA
    Verify.cases getSec zone dnskeys rankedAuthority msg zone SOA fromSOA nullSOA ($> []) $ \ps soaRRset cacheSOA -> do
        let doCache (soaDom, ncttl) = do
                cacheSOA
                withSection getRanked msg $ \_rrs rank -> cacheNegative soaDom dom typ ncttl rank
        either (ncWarn >>> ($> [])) (doCache >>> ($> soaRRset : nws)) $ single ps
  where
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
            orig <- (\q -> showQ "orig-query" [q]) <$> asksQC origQuestion_
            logLines lv $ ("cacheSectionNegative: " ++ unwords (withCtx $ key ++ query ++ orig)) : xs
        answer = DNS.answer msg
        soas = filter ((== SOA) . rrtype) $ DNS.authority msg

failWithCacheOrigName :: Ranking -> DNSError -> DNSQuery a
failWithCacheOrigName rank e = do
    Question dom _typ cls <- asksQC origQuestion_
    failWithCache dom Cache.ERR cls rank e

{- FOURMOLU_DISABLE -}
failWithCache :: Domain -> TYPE -> CLASS -> Ranking -> DNSError -> DNSQuery a
failWithCache dom typ cls rank e = do
    when (cls == IN) $ foldDNSErrorToRCODE (pure ()) (`cacheRCODE_` rank) e
    throwDnsError e
  where
    cacheRCODE_ = cacheRCODE dom typ
{- FOURMOLU_ENABLE -}

cacheDNSError :: (MonadIO m, MonadReader Env m) => Domain -> TYPE -> Ranking -> DNSError -> m ()
cacheDNSError dom typ rank e =
    foldDNSErrorToRCODE (pure ()) (`cacheRCODE_` rank) e
  where
    cacheRCODE_ = cacheRCODE dom typ

cacheNoData :: (MonadIO m, MonadReader Env m) => Domain -> TYPE -> Ranking -> m ()
cacheNoData dom typ rank = cacheRCODE dom typ NoErr rank

cacheRCODE :: (MonadIO m, MonadReader Env m) => Domain -> TYPE -> RCODE -> Ranking -> m ()
cacheRCODE dom typ rcode rank = do
    maxNegativeTTL <- asks maxNegativeTTL_
    cacheNegativeNoSOA rcode dom typ maxNegativeTTL rank

cacheNegative :: (MonadIO m, MonadReader Env m) => Domain -> Domain -> TYPE -> TTL -> Ranking -> m ()
cacheNegative zone dom typ ttl rank = do
    logLn Log.DEBUG $ "cacheNegative: " ++ show (zone, dom, typ, ttl, rank)
    insertRRSet <- asks insert_
    liftIO $ cpsInsertNegative zone dom typ ttl rank insertRRSet

cacheNegativeNoSOA :: (MonadIO m, MonadReader Env m) => RCODE -> Domain -> TYPE -> TTL -> Ranking -> m ()
cacheNegativeNoSOA rc dom typ ttl rank = do
    logLn Log.DEBUG $ "cacheNegativeNoSOA: " ++ show (rc, dom, typ, ttl, rank)
    insertRRSet <- asks insert_
    liftIO $ cpsInsertNegativeNoSOA rc dom typ ttl rank insertRRSet

{- FOURMOLU_DISABLE -}
cacheAnswer :: Delegation -> Domain -> TYPE -> DNSMessage -> DNSQuery ([RRset], [RRset])
cacheAnswer d@Delegation{..} dom typ msg = do
    getSec <- asks currentSeconds_
    (result, cacheX) <- verify getSec
    cacheX
    return result
  where
    qinfo = show dom ++ " " ++ show typ
    verify getSec = Verify.cases getSec zone dnskeys rankedAnswer msg dom typ Just nullX ncX $ \_ xRRset cacheX -> do
        nws <- witnessWildcardExpansion
        let (~verifyMsg, ~verifyColor, raiseOnVerifyFailure)
                {- TODO: add case for check-disabled -}
                | FilledDS [] <- delegationDS = ("no verification - no DS, " ++ qinfo, Just Yellow, pure ())
                | rrsetValid xRRset = ("verification success - RRSIG of " ++ qinfo, Just Green, pure ())
                | NotFilledDS o <- delegationDS = ("not consumed not-filled DS: case=" ++ show o ++ ", " ++ qinfo, Nothing, pure ())
                | otherwise = ("verification failed - RRSIG of " ++ qinfo, Just Red, throwDnsError DNS.ServerFailure)
        clogLn Log.DEMO verifyColor verifyMsg
        raiseOnVerifyFailure
        pure (([xRRset], nws), cacheX)
      where
        witnessWildcardExpansion = wildcardWitnessAction d dom typ msg

    nullX = doCacheEmpty <&> \e -> (([], e), pure ())
    doCacheEmpty = case rcode of
        {- authority sections for null answer -}
        DNS.NoErr      -> cacheSectionNegative zone dnskeys dom typ       rankedAnswer msg =<< witnessNoDatas
        DNS.NameErr    -> cacheSectionNegative zone dnskeys dom Cache.ERR rankedAnswer msg =<< witnessNameErr
        _ | crc rcode  -> cacheSectionNegative zone dnskeys dom typ       rankedAnswer msg []
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

{- FOURMOLU_DISABLE -}
cacheNoDelegation :: Delegation -> Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> DNSQuery ()
cacheNoDelegation d zone dnskeys dom msg
    | rcode == DNS.NoErr = cacheNoDataNS $> ()
    | rcode == DNS.NameErr = nameErrors $> ()
    | otherwise = pure ()
  where
    nameErrors = asks currentSeconds_ >>=
        \getSec -> Verify.cases getSec zone dnskeys rankedAnswer msg dom CNAME cnRD nullCNAME ncCNAME $
        \_rds _cnRRset cacheCNAME -> cacheCNAME *> cacheNoDataNS
    {- If you want to cache the NXDOMAIN of the CNAME destination, return it here.
       However, without querying the NS of the CNAME destination,
       you cannot obtain the record of rank that can be used for the reply. -}
    cnRD rr = DNS.fromRData $ rdata rr :: Maybe DNS.RD_CNAME
    nullCNAME = cacheSectionNegative zone dnskeys dom Cache.ERR rankedAuthority msg =<< witnessNameErr
    ncCNAME _ncLog = cacheNoDataNS
    {- not always possible to obtain NoData witness for NS
       * no NSEC/NSEC3 records - ex. A record exists
       * encloser NSEC/NSEC3 records for other than QNAME - ex. dig @ns1.dns-oarc.net. porttest.dns-oarc.net. A +dnssec -}
    cacheNoDataNS = cacheSectionNegative zone dnskeys dom NS rankedAuthority msg []
    (_witnessNoDatas, witnessNameErr) = negativeWitnessActions (pure []) d dom A msg
    rcode = DNS.rcode msg
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
wildcardWitnessAction :: Delegation -> Domain -> TYPE -> DNSMessage -> DNSQuery [RRset]
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
    resultK w rrsets _ = success w $> rrsets
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
                          resultK resultK resultK3 resultK3
    witnessNameError
        | noDS          = pure []
        | otherwise     = Verify.getNameError zone dnskeys rankedAuthority msg qname
                          nullK invalidK (noWitnessK "NameError")
                          resultK resultK3
    invalidK s = failed $ "NSEC/NSEC3 NameErr/NoData: " ++ qinfo ++ " :\n" ++ s
    noWitnessK wn s = failed $ "cannot find " ++ wn ++ " witness: " ++ qinfo ++ " : " ++ s
    resultK  w rrsets _ = success w *> winfo witnessInfoNSEC  w $> rrsets
    resultK3 w rrsets _ = success w *> winfo witnessInfoNSEC3 w $> rrsets
    success w = clogLn Log.DEMO (Just Green) $ "nsec verification success - " ++ SEC.witnessName w ++ ": " ++ qinfo
    winfo wi w = clogLn Log.DEMO (Just Cyan) $ unlines $ map ("  " ++) $ wi w
    failed = nsecFailed
    ~qinfo = show qname ++ " " ++ show qtype

    zone = delegationZone
    dnskeys = delegationDNSKEY
    noDS = case delegationDS of
        FilledDS [] -> True
        _           -> False
{- FOURMOLU_ENABLE -}

nsecFailed :: String -> DNSQuery a
nsecFailed s = (clogLn Log.DEMO (Just Red) $ "nsec verification failed - " ++ s) *> throwDnsError DNS.ServerFailure
