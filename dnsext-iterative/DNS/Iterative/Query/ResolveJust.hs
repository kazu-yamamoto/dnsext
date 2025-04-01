{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonadComprehensions #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.ResolveJust (
    -- * Iteratively search authritative server and exactly query to that
    runResolveExact,
    resolveExact,
    runIterative,

    -- * backword compatibility
    runResolveJust,
    resolveJust,

    -- * Root priming things
    refreshRoot,
    rootPriming,
) where

-- GHC packages
import Data.IORef (atomicWriteIORef, readIORef)
import qualified Data.List.NonEmpty as NE
import qualified Data.Set as Set

-- other packages

-- dnsext packages
import DNS.Do53.Client (QueryControls (..))
import qualified DNS.Log as Log
import DNS.RRCache (
    rankedAnswer,
    rankedAuthority,
 )
import qualified DNS.RRCache as Cache
import DNS.SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP)
import System.Console.ANSI.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Class
import DNS.Iterative.Query.Delegation
import DNS.Iterative.Query.Helpers
import qualified DNS.Iterative.Query.Norec as Norec
import DNS.Iterative.Query.Random
import qualified DNS.Iterative.Query.StubZone as Stub
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
import qualified DNS.Iterative.Query.Verify as Verify

---- import for doctest
import DNS.Iterative.Query.TestEnv

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -Wno-incomplete-uni-patterns
-- >>> import System.IO
-- >>> import qualified DNS.Types.Opaque as Opaque
-- >>> import DNS.SEC
-- >>> DNS.runInitIO addResourceDataForDNSSEC
-- >>> hSetBuffering stdout LineBuffering

-- test env use from doctest
_newTestEnv :: ([String] -> IO ()) -> IO Env
_newTestEnv putLines = newTestEnvNoCache putLines True

_findConsumed :: [String] -> IO ()
_findConsumed ss
    | any ("consumes not-filled DS:" `isInfixOf`) ss = putStrLn "consume message found"
    | otherwise = pure ()

_noLogging :: [String] -> IO ()
_noLogging = const $ pure ()

---

{-# DEPRECATED runResolveJust "use resolveExact instead of this" #-}
runResolveJust
    :: Env
    -> Domain
    -> TYPE
    -> QueryControls
    -> IO (Either QueryError (DNSMessage, Delegation))
runResolveJust = runResolveExact

-- 権威サーバーからの解決結果を得る
runResolveExact
    :: Env
    -> Domain
    -> TYPE
    -> QueryControls
    -> IO (Either QueryError (DNSMessage, Delegation))
runResolveExact cxt n typ cd = runDNSQuery (resolveExact n typ) cxt $ queryParamIN n typ cd

{-# DEPRECATED resolveJust "use resolveExact instead of this" #-}
resolveJust :: MonadQuery m => Domain -> TYPE -> m (DNSMessage, Delegation)
resolveJust = resolveExact

-- 反復検索を使って最終的な権威サーバーからの DNSMessage とその委任情報を得る. CNAME は解決しない.
resolveExact :: MonadQuery m => Domain -> TYPE -> m (DNSMessage, Delegation)
resolveExact = resolveExactDC 0

{- FOURMOLU_DISABLE -}
resolveExactDC :: MonadQuery m => Int -> Domain -> TYPE -> m (DNSMessage, Delegation)
resolveExactDC dc n typ
    | dc > mdc = do
        logLn Log.WARN $ unwords ["resolve-exact: not sub-level delegation limit exceeded:", show n, show typ]
        failWithCacheOrigName Cache.RankAnswer DNS.ServerFailure
    | otherwise = do
        anchor <- getAnchor
        (mmsg, nss) <- iterative dc anchor $ DNS.superDomains' (delegationZone anchor) n
        let reuseMsg msg
                | typ == requestDelegationTYPE  = do
                      logLn Log.DEMO $ unwords ["resolve-exact: skip exact query", show n, show typ, "for last no-delegation"]
                      pure (msg, nss)
                | otherwise                     = request nss
        maybe (request nss) reuseMsg mmsg
  where
    mdc = maxNotSublevelDelegation
    getAnchor = do
        stub <- asksEnv stubZones_
        maybe refreshRoot pure $ Stub.lookupStub stub n
    request nss@Delegation{..} = do
        checkEnabled <- getCheckEnabled
        short <- asksEnv shortLog_
        let withDO = checkEnabled && chainedStateDS nss && not (null delegationDNSKEY)
            ainfo sas = ["resolve-exact: query", show n, show typ] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]]
        delegationFallbacks dc withDO (logLn Log.DEMO . unwords . ainfo) nss n typ
{- FOURMOLU_ENABLE -}

maxNotSublevelDelegation :: Int
maxNotSublevelDelegation = 16

-- 反復後の委任情報を得る
runIterative
    :: Env
    -> Delegation
    -> Domain
    -> QueryControls
    -> IO (Either QueryError Delegation)
runIterative cxt sa n cd = runDNSQuery (snd <$> iterative 0 sa (DNS.superDomains n)) cxt $ queryParamIN n A cd

{- FOURMOLU_DISABLE -}
-- | 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威サーバー群を見つける
--
-- >>> testIterative dom = do { root <- refreshRoot; iterative 0 root (DNS.superDomains dom) }
-- >>> env <- _newTestEnv _findConsumed
-- >>> runDNSQuery (testIterative "mew.org.") env (queryParamIN "mew.org." A mempty) $> ()  {- fill-action is not called -}
--
-- >>> runDNSQuery (testIterative "arpa.") env (queryParamIN "arpa." NS mempty) $> ()  {- fill-action is called for `ServsChildZone` -}
-- consume message found
--
-- fst: last response message for not delegated last domain
-- snd: delegation for last domain
iterative :: MonadQuery m => Int -> Delegation -> [Domain] -> m (Maybe DNSMessage, Delegation)
iterative _  nss0  []       = pure (Nothing, nss0)
iterative dc nss0 (x : xs)  = do
    checkEnabled <- getCheckEnabled
    {- If NS is not returned, the information of the same NS is used for the child domain. or.jp and ad.jp are examples of this case. -}
    recurse . fmap (mayDelegation nss0 id) =<< step checkEnabled nss0
  where
    recurse (m, nss) = list1 (pure (m, nss)) (iterative dc nss) xs
    --                                       {- sub-level delegation. increase dc only not sub-level case. -}
    name = x

    stepQuery :: MonadQuery m => Bool -> Delegation -> m (DNSMessage, MayDelegation)
    stepQuery checkEnabled nss@Delegation{..} = do
        let zone = delegationZone
            dnskeys = delegationDNSKEY
        {- When the same NS information is inherited from the parent domain, balancing is performed by re-selecting the NS address. -}
        short <- asksEnv shortLog_
        let withDO = checkEnabled && chainedStateDS nss && not (null delegationDNSKEY)
            ainfo sas = ["iterative: query", show name, show A] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]]
        {- Use `A` for iterative queries to the authoritative servers during iterative resolution.
           See the following document:
           QNAME Minimisation Examples: https://datatracker.ietf.org/doc/html/rfc9156#section-4 -}
        (msg, _) <- delegationFallbacks dc withDO (logLn Log.DEMO . unwords . ainfo) nss name requestDelegationTYPE
        let withNoDelegation handler = mayDelegation handler (pure . hasDelegation)
            sharedHandler = servsChildZone dc nss name msg
            cacheHandler = cacheNoDelegation nss zone dnskeys name msg
            logDelegation' d = logDelegation d $> d
            handlers md =
                mapM logDelegation'                              =<<
                mapM fillCachedDelegation                        =<< {- fill from cache for fresh NS list -}
                withNoDelegation (cacheHandler $> noDelegation)  =<<
                withNoDelegation sharedHandler md
        (,) msg <$> (handlers =<< delegationWithCache zone dnskeys name msg)
    logDelegation Delegation{..} = do
        let zplogLn lv = logLn lv . (("zone: " ++ show delegationZone ++ ":\n") ++)
        short <- asksEnv shortLog_
        zplogLn Log.DEMO $ ppDelegation short delegationNS

    lookupERR :: MonadQuery m => m (Maybe RCODE)
    lookupERR = fmap fst <$> lookupErrorRCODE name
    withoutMsg md = pure (Nothing, md)
    withERRC rc = case rc of
        NameErr    -> withoutMsg noDelegation
        ServFail   -> throw' ServerFailure
        FormatErr  -> throw' FormatError
        Refused    -> throw' OperationRefused
        _          -> throw' ServerFailure
      where throw' e = logLn Log.DEMO ("iterative: " ++ show e ++ " with cached RCODE: " ++ show rc) *> throwDnsError e

    step :: MonadQuery m => Bool -> Delegation -> m (Maybe DNSMessage, MayDelegation)
    step checkEnabled nss@Delegation{..} = do
        let notDelegatedMsg (msg, md) = mayDelegation (Just msg, noDelegation) ((,) Nothing . hasDelegation) md
            stepQuery' = notDelegatedMsg <$> stepQuery checkEnabled nss
            getDelegation FreshD  = stepQuery' {- refresh for fresh parent -}
            getDelegation CachedD = lookupERR >>= maybe (lookupDelegation name >>= maybe stepQuery' withoutMsg) withERRC
            fills = mapM (fillsDNSSEC dc nss)
            --                                    {- fill for no A / AAAA cases aginst NS -}
        mapM fills =<< getDelegation delegationFresh
{- FOURMOLU_ENABLE -}

requestDelegationTYPE :: TYPE
requestDelegationTYPE = A

{- Workaround delegation for one authoritative server has both domain zone and sub-domain zone -}
servsChildZone :: MonadQuery m => Int -> Delegation -> Domain -> DNSMessage -> m MayDelegation
servsChildZone dc nss dom msg =
    handleSOA (handleASIG $ pure noDelegation)
  where
    handleSOA fallback = withSection rankedAuthority msg $ \srrs rank -> do
        let soaRRs = rrListWith SOA soaRD dom (\_ rr -> rr) srrs
        reqCD <- asksQP requestCD_
        case soaRRs of
            [] -> fallback
            [_] -> getWorkaround "SOA" >>= verifySOA reqCD
            _ : _ : _ -> multipleSOA rank soaRRs
      where
        soaRD rd = DNS.fromRData rd :: Maybe DNS.RD_SOA
        multipleSOA rank soaRRs = do
            logLn Log.WARN $ "servs-child: " ++ show dom ++ ": multiple SOAs are found:"
            logLn Log.DEMO $ show dom ++ ": multiple SOA: " ++ show soaRRs
            failWithCache dom Cache.ERR IN rank DNS.ServerFailure {- wrong child-zone  -}
        verifySOA reqCD wd
            | null dnskeys = pure $ hasDelegation wd
            | otherwise = Verify.cases reqCD dom dnskeys rankedAuthority msg dom SOA (soaRD . rdata) nullSOA ncSOA withSOA
          where
            dnskeys = delegationDNSKEY wd
            nullSOA = pure noDelegation {- guarded by soaRRs [] case -}
            ncSOA _ncLog = pure noDelegation {- guarded by soaRRs [_] case. single record must be canonical -}
            withSOA = Verify.withResult SOA (\s -> "servs-child: " ++ s ++ ": " ++ show dom) (\_ _ _ -> pure $ hasDelegation wd)
    handleASIG fallback = withSection rankedAnswer msg $ \srrs _rank -> do
        let arrsigRRs = rrListWith RRSIG (signedA <=< DNS.fromRData) dom (\_ rr -> rr) srrs
        case arrsigRRs of
            [] -> fallback
            _ : _ -> hasDelegation <$> getWorkaround "A-RRSIG"
      where
        {- Case when apex of cohabited child-zone has A record,
           * with DNSSEC, signed with child-zone apex.
           * without DNSSEC, indistinguishable from the A definition without sub-domain cohabitation -}
        signedA rd@RD_RRSIG{..} = guard (rrsig_type == A && rrsig_zone == dom) $> rd
    getWorkaround tag = do
        logLn Log.DEMO $ "servs-child: workaround: " ++ tag ++ ": " ++ show dom ++ " may be provided with " ++ show (delegationZone nss)
        fillsDNSSEC dc nss (Delegation dom (delegationNS nss) (NotFilledDS ServsChildZone) [] (delegationFresh nss))

fillsDNSSEC :: MonadQuery m => Int -> Delegation -> Delegation -> m Delegation
fillsDNSSEC dc nss d = do
    reqCD <- asksQP requestCD_
    fillsDNSSEC' reqCD dc nss d

{- FOURMOLU_DISABLE -}
fillsDNSSEC' :: MonadQuery m => RequestCD -> Int -> Delegation -> Delegation -> m Delegation
fillsDNSSEC' CheckDisabled   _dc _nss d = pure d
fillsDNSSEC' NoCheckDisabled  dc  nss d = do
    filled@Delegation{..} <- fillDelegationDNSKEY dc =<< fillDelegationDS dc nss d
    when (chainedStateDS filled && null delegationDNSKEY) $ do
        let zone = show delegationZone
        logLn Log.WARN $ "require-ds-and-dnskey: " ++ zone ++ ": DS is 'chained'-state, and DNSKEY is null"
        clogLn Log.DEMO (Just Red) $ zone ++ ": verification error. dangling DS chain. DS exists, and DNSKEY does not exists"
        throwDnsError DNS.ServerFailure
    return filled
{- FOURMOLU_ENABLE -}

getCheckEnabled :: MonadQuery m => m Bool
getCheckEnabled = noCD <$> asksQP requestCD_
  where
    noCD NoCheckDisabled = True
    noCD CheckDisabled = False

-- | Fill DS for delegation info. The result must be `FilledDS` for success query.
--
-- >>> Right dummyKey = Opaque.fromBase64 "dummykey///dummykey///dummykey///dummykey///"
-- >>> dummyDNSKEY = RD_DNSKEY [ZONE] 3 RSASHA256 $ toPubKey RSASHA256 dummyKey
-- >>> Right dummyDS_ = Opaque.fromBase16 "0123456789ABCD0123456789ABCD0123456789ABCD0123456789ABCD"
-- >>> dummyDS = RD_DS 0 RSASHA256 SHA256 dummyDS_
-- >>> withNS2 dom h1 a1 h2 a2 ds = Delegation dom (DEwithA4 h1 (a1:|[]) :| [DEwithA4 h2 (a2:|[])]) ds [dummyDNSKEY] FreshD
-- >>> parent = withNS2 "org." "a0.org.afilias-nst.info." "199.19.56.1" "a2.org.afilias-nst.info." "199.249.112.1" (FilledDS [dummyDS])
-- >>> mkChild ds = withNS2 "mew.org." "ns1.mew.org." "202.238.220.92" "ns2.mew.org." "210.155.141.200" ds
-- >>> isFilled d = case (delegationDS d) of { NotFilledDS {} -> False; FilledDS {} -> True; AnchorSEP {} -> True }
-- >>> env <- _newTestEnv _noLogging
-- >>> runChild child = runDNSQuery (fillDelegationDS 0 parent child) env (queryParamIN "ns1.mew.org." A mempty)
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS CachedDelegation)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS ServsChildZone)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ FilledDS [])
-- Right True
fillDelegationDS :: MonadQuery m => Int -> Delegation -> Delegation -> m Delegation
fillDelegationDS dc src dest
    | null $ delegationDNSKEY src = fill [] {- no src DNSKEY, not chained -}
    | NotFilledDS o <- delegationDS src = do
        logLn Log.WARN $ "require-ds: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show (delegationZone src)
        return dest
    | FilledDS [] <- delegationDS src = fill [] {- no src DS, not chained -}
    | Delegation{..} <- dest = case delegationDS of
        AnchorSEP{} -> pure dest {- specified trust-anchor dnskey case -}
        FilledDS _ -> pure dest {- no DS or exist DS, anyway filled DS -}
        NotFilledDS o -> do
            logLn Log.DEMO $ "require-ds: consumes not-filled DS: case=" ++ show o ++ " zone: " ++ show delegationZone
            maybe query fill =<< lookupDS delegationZone
  where
    dsRDs (rrs, _rank) = Just [rd | rr <- rrs, Just rd <- [DNS.fromRData $ rdata rr]]
    lookupDS :: MonadQuery m => Domain -> m (Maybe [RD_DS])
    lookupDS zone = lookupValidRR "require-ds" zone DS <&> (>>= dsRDs)
    fill dss = pure dest{delegationDS = FilledDS dss}
    query = fillCachedDelegation =<< fill =<< queryDS dc src (delegationZone dest)

{- FOURMOLU_DISABLE -}
queryDS :: MonadQuery m => Int -> Delegation -> Domain -> m [RD_DS]
queryDS dc src@Delegation{..} dom = do
    short <- asksEnv shortLog_
    let ainfo sas = ["require-ds: query", show zone, show DS] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]]
    (msg, _) <- delegationFallbacks dc True (logLn Log.DEMO . unwords . ainfo) src dom DS
    Verify.cases NoCheckDisabled zone dnskeys rankedAnswer msg dom DS (DNS.fromRData . rdata) nullDS ncDS withDS
  where
    nullDS = insecure "no DS, so no verify" $> []
    ncDS ncLog = ncLog *> bogus "not canonical DS"
    withDS dsrds = Verify.withResult DS msgf (\_ _ _ -> pure dsrds) dsrds  {- not reach for no-verify and check-disabled cases -}
    insecure ~vmsg = Verify.insecureLog (msgf vmsg)
    bogus ~es = Verify.bogusError (msgf es)
    msgf s = "fill delegation - " ++ s ++ ": " ++ domTraceMsg
    domTraceMsg = show zone ++ " -> " ++ show dom
    zone = delegationZone
    dnskeys = delegationDNSKEY
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
refreshRoot :: MonadQuery m => m Delegation
refreshRoot = do
    curRef <- asksEnv currentRoot_
    let refresh = do
            n <- getRoot
            liftIO $ atomicWriteIORef curRef $ Just n{delegationFresh = CachedD} {- got from IORef as cached -}
            return n
        keep = do
            current <- liftIO $ readIORef curRef
            maybe refresh return current
        checkLife = do
            nsc <- lookupRR "." NS
            maybe refresh (const keep) nsc
    checkLife
  where
    getRoot = do
        let fallback s = do
                {- fallback to rootHint -}
                logLn Log.WARN $ "refreshRoot: " ++ s
                asksEnv rootHint_
        either fallback return =<< rootPriming
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
{-
steps of root priming
1. get DNSKEY RRset of root-domain using `fillDelegationDNSKEY` steps
2. query NS from root-domain with DO flag - get NS RRset and RRSIG
3. verify NS RRset of root-domain with RRSIGa
 -}
rootPriming :: MonadQuery m => m (Either String Delegation)
rootPriming =
    priming =<< fillDelegationDNSKEY 0 =<< getHint
  where
    left s = Left $ "root-priming: " ++ s
    logResult delegationNS color s = do
        clogLn Log.DEMO (Just color) $ "root-priming: " ++ s
        short <- asksEnv shortLog_
        logLn Log.DEMO $ ppDelegation short delegationNS
    nullNS = pure $ left "no NS RRs"
    ncNS _ncLog = pure $ left "not canonical NS RRs"
    pairNS rr = (,) <$> rdata rr `DNS.rdataField` DNS.ns_domain <*> pure rr

    verify hint msgNS = Verify.cases NoCheckDisabled "." dnskeys rankedAnswer msgNS "." NS pairNS nullNS ncNS $
        \nsps nsRRset postAction -> do
            let nsSet = Set.fromList $ map fst nsps
                (axRRs, cacheAX) = withSection Cache.rankedAdditional msgNS $ \rrs rank ->
                    (axList False (`Set.member` nsSet) (\_ rr -> rr) rrs, cacheSection axRRs rank)
                result "."  ents
                    | not $ rrsetValid nsRRset = do
                          postAction  {- Call action for logging error info. `Verify.cacheRRset` does not cache invalids -}
                          logResult ents Red "verification failed - RRSIG of NS: \".\"" $> left "DNSSEC verification failed"
                    | otherwise                = do
                          postAction *> cacheAX
                          logResult ents Green "verification success - RRSIG of NS: \".\""
                          pure $ Right $ hint{delegationNS = ents, delegationFresh = FreshD}
                result apex _ents = pure $ left $ "inconsistent zone apex: " ++ show apex ++ ", not \".\""
            fromMaybe (pure $ left "no delegation") $ findDelegation' result nsps axRRs
      where
        dnskeys = delegationDNSKEY hint

    getHint = do
        hint <- asksEnv rootHint_
        anchor <- asksEnv rootAnchor_
        pure hint{delegationDS = anchor}
    priming hint = do
        let short = False
        let zone = "."
            ainfo sas = ["root-priming: query", show zone, show NS] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]]
        (msgNS, _) <- delegationFallbacks 0 True (logLn Log.DEMO . unwords . ainfo) hint zone NS
        verify hint msgNS
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY :: MonadQuery m => Int -> Delegation -> m Delegation
fillDelegationDNSKEY _dc d@Delegation{delegationDS = NotFilledDS o, delegationZone = zone} = do
    {- DS(Delegation Signer) is not filled -}
    logLn Log.WARN $ "require-dnskey: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show zone
    pure d
fillDelegationDNSKEY _dc d@Delegation{delegationDS = FilledDS []} = pure d {- DS(Delegation Signer) does not exist -}
fillDelegationDNSKEY  dc d@Delegation{..} = fillDelegationDNSKEY' getSEP dc d
  where
    zone = delegationZone
    getSEP = case delegationDS of
        AnchorSEP _ sep     -> \_ -> Right sep
        FilledDS dss@(_:_)  -> (fmap fst <$>) . Verify.sepDNSKEY dss zone . rrListWith DNSKEY DNS.fromRData zone const
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY' :: MonadQuery m => ([RR] -> Either String (NonEmpty RD_DNSKEY)) -> Int -> Delegation -> m Delegation
fillDelegationDNSKEY' _      _dc d@Delegation{delegationDNSKEY = _:_}     = pure d
fillDelegationDNSKEY' getSEP  dc d@Delegation{delegationDNSKEY = [] , ..} =
    maybe query (fill d . toDNSKEYs) =<< lookupValidRR "require-dnskey" zone DNSKEY
  where
    zone = delegationZone
    toDNSKEYs (rrs, _rank) = [rd | rr <- rrs, Just rd <- [DNS.fromRData $ rdata rr]]
    fill d' dnskeys = pure d'{delegationDNSKEY = dnskeys}
    query = cachedDNSKEY getSEP dc d >>= \(ks, d') -> fill d' ks
{- FOURMOLU_ENABLE -}

{-
steps to get verified and cached DNSKEY RRset
1. query DNSKEY from delegatee with DO flag - get DNSKEY RRset and its RRSIG
2. verify SEP DNSKEY of delegatee with DS
3. verify DNSKEY RRset of delegatee with RRSIG
4. cache DNSKEY RRset with RRSIG when validation passes
 -}
cachedDNSKEY
    :: MonadQuery m => ([RR] -> Either String (NonEmpty RD_DNSKEY)) -> Int -> Delegation -> m ([RD_DNSKEY], Delegation)
cachedDNSKEY getSEPs dc d@Delegation{..} = do
    short <- asksEnv shortLog_
    let ainfo sas = ["require-dnskey: query", show zone, show DNSKEY] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]]
    (msg, d') <- delegationFallbacks dc True (logLn Log.DEMO . unwords . ainfo) d zone DNSKEY
    let rcode = DNS.rcode msg
    case rcode of
        DNS.NoErr -> withSection rankedAnswer msg $ \srrs _rank ->
            either bogus (fmap (\ks -> (ks, d')) . verifyDNSKEY msg) $ getSEPs srrs
        _ -> bogus $ "error rcode to get DNSKEY: " ++ show rcode
  where
    verifyDNSKEY msg (s :| ss) = do
        let dnskeyRD rr = DNS.fromRData $ rdata rr :: Maybe RD_DNSKEY
            {- no DNSKEY case -}
            nullDNSKEY = cacheSectionNegative zone [] zone DNSKEY rankedAnswer msg [] *> bogus "null DNSKEYs for non-empty SEP"
            ncDNSKEY ncLog = ncLog >> bogus "not canonical"
        Verify.cases NoCheckDisabled zone (s : ss) rankedAnswer msg zone DNSKEY dnskeyRD nullDNSKEY ncDNSKEY withDNSKEY
    withDNSKEY rds = Verify.withResult DNSKEY msgf (\_ _ _ -> pure rds) rds {- not reach for no-verify and check-disabled cases -}
    bogus ~es = Verify.bogusError (msgf es)
    msgf s = "require-dnskey: " ++ s ++ ": " ++ show zone
    zone = delegationZone

---

{- FOURMOLU_DISABLE -}
delegationFallbacks
    :: MonadQuery m
    => Int -> Bool -> ([Address] -> m b)
    -> Delegation -> Domain -> TYPE -> m (DNSMessage, Delegation)
delegationFallbacks dc dnssecOK ah d0 name typ = do
    disableV6NS <- asksEnv disableV6NS_
    delegationFallbacks_ handled failed qparallel disableV6NS dc dnssecOK ah d0 name typ
  where
    handled = logLn Log.DEMO
    failed ass = logLines Log.DEMO ("delegationFallbacks: failed:" : ["  " ++ unwords (ns : map pprAddr as) | (ns, as) <- ass])
    qparallel = 2
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
delegationFallbacks_
    :: MonadQuery m
    => (String -> m c)
    -> ([(String, [Address])] -> m a)
    -> Int -> Bool -> Int -> Bool -> ([Address] -> m b)
    -> Delegation -> Domain -> TYPE -> m (DNSMessage, Delegation)
delegationFallbacks_ eh fh qparallel disableV6NS dc dnssecOK ah d0@Delegation{..} name typ = do
    paxs1  <- dentryToPermAx disableV6NS dentry
    pnss   <- dentryToPermNS zone dentry
    fallbacks id d0 ("<cached>", \d n j -> list (n d) (\a as -> j d $ a :| as) paxs1) [(show ns, resolveNS' ns) | ns <- pnss]
  where
    dentry = NE.toList delegationNS
    fallbacks aa d (tag, runAxs) runsAxs = runAxs d emp ne
      where
        emp d' = list (fh (aa []) >> throwDnsError ServerFailure) (fallbacks (aa . ((tag, []):)) d') runsAxs
        ne d' paxs = list step (\g gs -> step `catchQuery` \e -> hlog e >> fallbacks (aa . ((tag, paxs'):)) d' g gs) runsAxs
          where
            step = case [ah (NE.toList axc) >> norec dnssecOK axc name typ | axc <- chunksOfNE qparallel paxs] of
                f:|fs -> (,) <$> catches f fs <*> pure d'
            paxs' = NE.toList paxs
            hlog e = eh' $ unwords $ show e : "for" : map show paxs'
    catches x  []     = x
    catches x (y:xs)  = x `catchQuery` \_e -> catches y xs

    resolveNS' ns d emp ne = do
        {- tryError idiom, before mtl 2.3 -}
        e <- (Right <$> resolveNS zone disableV6NS dc ns) `catchQuery` (pure . Left)
        d' <- fillCachedDelegation d
        either left (either rleft rright) e d'
      where
        left e d' = eh' (show e ++ " for resolving " ++ show ns) >> emp d'
        rleft (_rc, ei) d' = eh' ei >> emp d'
        rright axs d' = ne d' =<< randomizedPermN [(ip, 53) | (ip, _) <- axs]
    eh' = eh . ("delegationFallbacks: " ++)

    zone = delegationZone
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
resolveNS :: MonadQuery m => Domain -> Bool -> Int -> Domain -> m (Either (RCODE, String) (NonEmpty (IP, RR)))
resolveNS zone disableV6NS dc ns = do
    (rc, axs) <- query1Ax
    list (failEmptyAx rc) (\a as -> pure $ Right $ a :| as) axs
  where
    axPairs = axList disableV6NS (== ns) (,)

    query1Ax
        | disableV6NS = querySection A
        | otherwise = join $ randomizedChoice q46 q64
      where
        q46 = A +!? AAAA
        q64 = AAAA +!? A
        tx +!? ty = do
            x@(rc, xs) <- querySection tx
            {- not fallback for NameErr case -}
            if rc == NoErr && null xs then querySection ty else pure x
        querySection typ = do
            logLn Log.DEMO $ unwords ["resolveNS:", show (ns, typ), "dc:" ++ show dc, "->", show (succ dc)]
            {- resolve for not sub-level delegation. increase dc (delegation count) -}
            cacheAnswerAx typ =<< resolveExactDC (succ dc) ns typ
        cacheAnswerAx typ (msg, d) = do
            cacheAnswer d ns typ msg $> ()
            pure (rcode msg, withSection rankedAnswer msg $ \rrs _rank -> axPairs rrs)

    failEmptyAx rc = do
        let emptyInfo = if disableV6NS then "empty A (disable-v6ns)" else "empty A|AAAA"
        orig <- showQ "orig-query:" <$> asksQP origQuestion_
        let errorInfo = (if rc == NoErr then emptyInfo else show rc) ++ " for NS,"
        pure $ Left (rc, unwords $ errorInfo : ["ns: " ++ show ns ++ ",", "zone: " ++ show zone ++ ",", orig])
{- FOURMOLU_ENABLE -}

---

maxQueryCount :: Int
maxQueryCount = 64

norec :: MonadQuery m => Bool -> NonEmpty Address -> Domain -> TYPE -> m DNSMessage
norec dnssecOK aservers name typ = do
    qcount <- (NE.length aservers +) <$> getQS queryCounter_
    logLn Log.DEBUG ("query count: " ++ show qcount)
    orig <- showQ "orig-query" <$> asksQP origQuestion_
    setQS queryCounter_ qcount
    setQS lastQuery_ (Question name typ IN, NE.toList aservers)
    m <- dispatch qcount orig
    setQS aservMessage_ $ Just m
    pure m
  where
    dispatch qcount orig
        | qcount > maxQueryCount = logLn Log.WARN (exceeded orig) >> left ServerFailure
        | otherwise = Norec.norec' dnssecOK aservers name typ >>= either left handleResponse
    exceeded orig = "max-query-count (==" ++ show maxQueryCount ++ ") exceeded: " ++ showQ' "query" name typ ++ ", " ++ orig
    handleResponse = handleResponseError (NE.toList aservers) throwQuery pure
    left e = cacheDNSError name typ Cache.RankAnswer e >> dnsError e
    dnsError e = throwQuery $ uncurry DnsError $ unwrapDNSErrorInfo e
