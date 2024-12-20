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
import DNS.Iterative.Query.Delegation
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Random
import qualified DNS.Iterative.Query.StubZone as Stub
import qualified DNS.Iterative.Query.Norec as Norec
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
resolveJust :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJust = resolveExact

-- 反復検索を使って最終的な権威サーバーからの DNSMessage とその委任情報を得る. CNAME は解決しない.
resolveExact :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveExact = resolveExactDC 0

{- FOURMOLU_DISABLE -}
resolveExactDC :: Int -> Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveExactDC dc n typ
    | dc > mdc = do
        logLn Log.WARN $ unwords ["resolve-exact: not sub-level delegation limit exceeded:", show n, show typ]
        failWithCacheOrigName Cache.RankAnswer DNS.ServerFailure
    | otherwise = do
        anchor <- getAnchor
        (mmsg, nss) <- iterative_ dc anchor $ DNS.superDomains' (delegationZone anchor) n
        let reuseMsg msg
                | typ == requestDelegationTYPE  = do
                      logLn Log.DEMO $ unwords ["resolve-exact: skip exact query", show n, show typ, "for last no-delegation"]
                      pure (msg, nss)
                | otherwise                     = request nss
        maybe (request nss) reuseMsg mmsg
  where
    mdc = maxNotSublevelDelegation
    getAnchor = do
        stub <- asks stubZones_
        maybe refreshRoot pure $ Stub.lookupStub stub n
    request nss@Delegation{..} = do
        checkEnabled <- getCheckEnabled
        short <- asks shortLog_
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
runIterative cxt sa n cd = runDNSQuery (snd <$> iterative sa n) cxt $ queryParamIN n A cd

-- | 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威サーバー群を見つける
--
-- >>> testIterative dom = do { root <- refreshRoot; iterative root dom }
-- >>> env <- _newTestEnv _findConsumed
-- >>> runDNSQuery (testIterative "mew.org.") env (queryParamIN "mew.org." A mempty) $> ()  {- fill-action is not called -}
--
-- >>> runDNSQuery (testIterative "arpa.") env (queryParamIN "arpa." NS mempty) $> ()  {- fill-action is called for `ServsChildZone` -}
-- consume message found
iterative :: Delegation -> Domain -> DNSQuery (Maybe DNSMessage, Delegation)
iterative sa n = iterative_ 0 sa $ DNS.superDomains n

{- FOURMOLU_DISABLE -}
-- fst: last response message for not delegated last domain
-- snd: delegation for last domain
iterative_ :: Int -> Delegation -> [Domain] -> DNSQuery (Maybe DNSMessage, Delegation)
iterative_ _  nss0  []       = pure (Nothing, nss0)
iterative_ dc nss0 (x : xs)  = do
    checkEnabled <- getCheckEnabled
    {- If NS is not returned, the information of the same NS is used for the child domain. or.jp and ad.jp are examples of this case. -}
    recurse . fmap (mayDelegation nss0 id) =<< step checkEnabled nss0
  where
    recurse (m, nss) = list1 (pure (m, nss)) (iterative_ dc nss) xs
    --                                       {- sub-level delegation. increase dc only not sub-level case. -}
    name = x

    stepQuery :: Bool -> Delegation -> DNSQuery (DNSMessage, MayDelegation)
    stepQuery checkEnabled nss@Delegation{..} = do
        let zone = delegationZone
            dnskeys = delegationDNSKEY
        {- When the same NS information is inherited from the parent domain, balancing is performed by re-selecting the NS address. -}
        short <- asks shortLog_
        let withDO = checkEnabled && chainedStateDS nss && not (null delegationDNSKEY)
            ainfo sas = ["iterative: query", show name, show A] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]]
        {- Use `A` for iterative queries to the authoritative servers during iterative resolution.
           See the following document:
           QNAME Minimisation Examples: https://datatracker.ietf.org/doc/html/rfc9156#section-4 -}
        (msg, _) <- delegationFallbacks dc withDO (logLn Log.DEMO . unwords . ainfo) nss name requestDelegationTYPE
        let withNoDelegation handler = mayDelegation handler (pure . hasDelegation)
            sharedHandler = servsChildZone nss name msg
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
        short <- asks shortLog_
        zplogLn Log.DEMO $ ppDelegation short delegationNS

    lookupERR = fmap fst <$> lookupErrorRCODE name
    withoutMsg md = pure (Nothing, md)
    withERRC rc = case rc of
        NameErr    -> withoutMsg noDelegation
        ServFail   -> throw' ServerFailure
        FormatErr  -> throw' FormatError
        Refused    -> throw' OperationRefused
        _          -> throw' ServerFailure
      where throw' e = logLn Log.DEMO ("iterative: " ++ show e ++ " with cached RCODE: " ++ show rc) *> throwDnsError e

    step :: Bool -> Delegation -> DNSQuery (Maybe DNSMessage, MayDelegation)
    step checkEnabled nss@Delegation{..} = do
        let notDelegatedMsg (msg, md) = mayDelegation (Just msg, noDelegation) ((,) Nothing . hasDelegation) md
            stepQuery' = notDelegatedMsg <$> stepQuery checkEnabled nss
            getDelegation FreshD  = stepQuery' {- refresh for fresh parent -}
            getDelegation CachedD = lookupERR >>= maybe (lookupDelegation name >>= maybe stepQuery' withoutMsg) withERRC
            fills md = mapM (fillsDNSSEC nss) =<< mapM (fillDelegation dc) md
            --                                    {- fill for no A / AAAA cases aginst NS -}
        mapM fills =<< getDelegation delegationFresh
{- FOURMOLU_ENABLE -}

requestDelegationTYPE :: TYPE
requestDelegationTYPE = A

{- Workaround delegation for one authoritative server has both domain zone and sub-domain zone -}
servsChildZone :: Delegation -> Domain -> DNSMessage -> DNSQuery MayDelegation
servsChildZone nss dom msg =
    handleSOA (handleASIG $ pure noDelegation)
  where
    handleSOA fallback = withSection rankedAuthority msg $ \srrs rank -> do
        let soaRRs = rrListWith SOA soaRD dom (\_ rr -> rr) srrs
        reqQC <- asksQP requestCD_
        case soaRRs of
            [] -> fallback
            [_] -> getWorkaround "SOA" >>= verifySOA reqQC
            _ : _ : _ -> multipleSOA rank soaRRs
      where
        soaRD rd = DNS.fromRData rd :: Maybe DNS.RD_SOA
        multipleSOA rank soaRRs = do
            logLn Log.WARN $ "servs-child: " ++ show dom ++ ": multiple SOAs are found:"
            logLn Log.DEMO $ show dom ++ ": multiple SOA: " ++ show soaRRs
            failWithCache dom Cache.ERR IN rank DNS.ServerFailure {- wrong child-zone  -}
        verifySOA reqQC wd
            | null dnskeys = pure $ hasDelegation wd
            | otherwise = Verify.cases reqQC zone dnskeys rankedAuthority msg dom SOA (soaRD . rdata) nullSOA ncSOA result
          where
            zone = delegationZone wd
            dnskeys = delegationDNSKEY wd
            nullSOA = pure noDelegation {- guarded by soaRRs [] case -}
            ncSOA _ncLog = pure noDelegation {- guarded by soaRRs [_] case. single record must be canonical -}
            result _ soaRRset _cacheSOA
                | rrsetValid soaRRset = pure $ hasDelegation wd
                | otherwise = verificationError
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
    verificationError = do
        logLn Log.WARN $ "servs-child: " ++ show dom ++ ": verification error. invalid SOA:"
        clogLn Log.DEMO (Just Red) $ show dom ++ ": verification error. invalid SOA"
        throwDnsError DNS.ServerFailure
    getWorkaround tag = do
        logLn Log.DEMO $ "servs-child: workaround: " ++ tag ++ ": " ++ show dom ++ " may be provided with " ++ show (delegationZone nss)
        fillsDNSSEC nss (Delegation dom (delegationNS nss) (NotFilledDS ServsChildZone) [] (delegationFresh nss))

fillsDNSSEC :: Delegation -> Delegation -> DNSQuery Delegation
fillsDNSSEC nss d = do
    reqCD <- asksQP requestCD_
    fillsDNSSEC' reqCD nss d

{- FOURMOLU_DISABLE -}
fillsDNSSEC' :: RequestCD -> Delegation -> Delegation -> DNSQuery Delegation
fillsDNSSEC' CheckDisabled   _nss d = pure d
fillsDNSSEC' NoCheckDisabled  nss d = do
    filled@Delegation{..} <- fillDelegationDNSKEY =<< fillDelegationDS nss d
    when (chainedStateDS filled && null delegationDNSKEY) $ do
        let zone = show delegationZone
        logLn Log.WARN $ "require-ds-and-dnskey: " ++ zone ++ ": DS is 'chained'-state, and DNSKEY is null"
        clogLn Log.DEMO (Just Red) $ zone ++ ": verification error. dangling DS chain. DS exists, and DNSKEY does not exists"
        throwDnsError DNS.ServerFailure
    return filled
{- FOURMOLU_ENABLE -}

getCheckEnabled :: MonadReaderQP m => m Bool
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
-- >>> runChild child = runDNSQuery (fillDelegationDS parent child) env (queryParamIN "ns1.mew.org." A mempty)
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS CachedDelegation)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS ServsChildZone)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ FilledDS [])
-- Right True
fillDelegationDS :: Delegation -> Delegation -> DNSQuery Delegation
fillDelegationDS src dest
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
            maybe (list1 nullAddrs query =<< delegationIPs src) fill =<< lookupDS delegationZone
  where
    dsRDs (rrs, _rank) = Just [rd | rr <- rrs, Just rd <- [DNS.fromRData $ rdata rr]]
    lookupDS :: Domain -> DNSQuery (Maybe [RD_DS])
    lookupDS zone = lookupValidRR "require-ds" zone DS <&> (>>= dsRDs)
    fill dss = pure dest{delegationDS = FilledDS dss}
    nullAddrs = logLn Log.WARN "require-ds: address list is null" $> dest
    verifyFailed ~es = logLn Log.WARN ("require-ds: " ++ es) *> throwDnsError DNS.ServerFailure
    query sas = do
        let zone = delegationZone dest
            result (e, ~verifyColor, ~verifyMsg) = do
                let domTraceMsg = show (delegationZone src) ++ " -> " ++ show zone
                clogLn Log.DEMO (Just verifyColor) $ "fill delegation - " ++ verifyMsg ++ ": " ++ domTraceMsg
                either verifyFailed fill e
        short <- asks shortLog_
        logLn Log.DEMO $ unwords (["require-ds: query", show zone, show DS] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]])
        result =<< queryDS (delegationZone src) (delegationDNSKEY src) sas zone

queryDS
    :: Domain
    -> [RD_DNSKEY]
    -> [Address]
    -> Domain
    -> DNSQuery (Either String [RD_DS], Color, String)
queryDS zone dnskeys ips dom = do
    msg <- norec True ips dom DS
    Verify.cases NoCheckDisabled zone dnskeys rankedAnswer msg dom DS (DNS.fromRData . rdata) nullDS ncDS verifyResult
  where
    nullDS = pure (Right [], Yellow, "no DS, so no verify")
    ncDS _ncLog = pure (Left "queryDS: not canonical DS", Red, "not canonical DS")
    verifyResult dsrds dsRRset cacheDS
        | rrsetValid dsRRset = cacheDS $> (Right dsrds, Green, "verification success - RRSIG of DS")
        | otherwise = pure (Left "queryDS: verification failed - RRSIG of DS", Red, "verification failed - RRSIG of DS")

{- FOURMOLU_DISABLE -}
fillDelegation :: Int -> Delegation -> DNSQuery Delegation
fillDelegation dc d0 = do
    disableV6NS <- asks disableV6NS_
    fillCachedDelegation =<< fillDelegationOnNull dc disableV6NS d0
    {- lookup again for updated cache with resolveNS -}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- Fill delegation with resolved IPs
-- If no available NS is found, ServerFailure is returned.
fillDelegationOnNull :: Int -> Bool -> Delegation -> DNSQuery Delegation
fillDelegationOnNull dc disableV6NS d0@Delegation{..}
    | dentryIPnull disableV6NS dentry  = case nonEmpty names of
        Nothing      -> do
            orig <- showQ "orig-query:" <$> asksQP origQuestion_
            logLines Log.DEMO
                [ "fillDelegationOnNullIP: serv-fail: delegation is empty."
                , "  zone: " ++ show zone
                , "  " ++ orig
                , "  disable-v6-ns: " ++ show disableV6NS
                , "  without-glue sub-domains:" ++ show subNames
                ]
            throwDnsError DNS.ServerFailure
        Just names1  -> do
            name <- randomizedSelectN names1
            let right = foldIPnonEmpty (DEwithA4 name) (DEwithA6 name) (DEwithAx name) . fmap fst
                left (rc, ei) = logLn Log.WARN $ unwords ["resolveNS failed,", "rcode: " ++ show rc ++ ",", ei]
            filled <- either ((>> throwDnsError ServerFailure) . left) (pure . right) =<< resolveNS zone disableV6NS dc name
            pure $ d0{delegationNS = replaceTo name filled delegationNS}
    | otherwise       = pure d0
  where
    zone = delegationZone
    dentry = NE.toList delegationNS

    names = foldr takeNames [] delegationNS
    takeNames (DEonlyNS name) xs
        | not (name `DNS.isSubDomainOf` zone)  = name : xs
    --    {- skip sub-domain without glue to avoid loop -}
    takeNames  _              xs               =        xs

    replaceTo n alt des = NE.map replace des
      where
        replace (DEonlyNS name)
            | name == n     = alt
        replace  de         = de

    subNames = foldr takeSubNames [] delegationNS
    takeSubNames (DEonlyNS name) xs
        | name `DNS.isSubDomainOf` zone  = name : xs {- sub-domain name without glue -}
    takeSubNames _ xs                    =        xs
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
refreshRoot :: DNSQuery Delegation
refreshRoot = do
    curRef <- asks currentRoot_
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
                asks rootHint_
        either fallback return =<< rootPriming
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
{-
steps of root priming
1. get DNSKEY RRset of root-domain using `fillDelegationDNSKEY` steps
2. query NS from root-domain with DO flag - get NS RRset and RRSIG
3. verify NS RRset of root-domain with RRSIGa
 -}
rootPriming :: DNSQuery (Either String Delegation)
rootPriming =
    priming =<< fillDelegationDNSKEY =<< getHint
  where
    left s = Left $ "root-priming: " ++ s
    logResult delegationNS color s = do
        clogLn Log.DEMO (Just color) $ "root-priming: " ++ s
        short <- asks shortLog_
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
        hint <- asks rootHint_
        anchor <- asks rootAnchor_
        pure hint{delegationDS = anchor}
    priming hint = do
        sas <- delegationIPs hint
        let zone = "."
        let short = False
        logLn Log.DEMO $ unwords (["root-priming: query", show zone, show NS] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]])
        msgNS <- norec True sas zone NS
        verify hint msgNS
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY :: Delegation -> DNSQuery Delegation
fillDelegationDNSKEY d@Delegation{delegationDS = NotFilledDS o, delegationZone = zone} = do
    {- DS(Delegation Signer) is not filled -}
    logLn Log.WARN $ "require-dnskey: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show zone
    pure d
fillDelegationDNSKEY d@Delegation{delegationDS = FilledDS []} = pure d {- DS(Delegation Signer) does not exist -}
fillDelegationDNSKEY d@Delegation{..} = fillDelegationDNSKEY' getSEP d
  where
    zone = delegationZone
    getSEP = case delegationDS of
        AnchorSEP _ sep     -> \_ -> Right sep
        FilledDS dss@(_:_)  -> (fmap fst <$>) . Verify.sepDNSKEY dss zone . rrListWith DNSKEY DNS.fromRData zone const
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY' :: ([ResourceRecord] -> Either String (NonEmpty RD_DNSKEY)) -> Delegation -> DNSQuery Delegation
fillDelegationDNSKEY' _      d@Delegation{delegationDNSKEY = _:_}     = pure d
fillDelegationDNSKEY' getSEP d@Delegation{delegationDNSKEY = [] , ..} =
    maybe (list1 nullIPs query =<< delegationIPs d) (fill . toDNSKEYs) =<< lookupValidRR "require-dnskey" zone DNSKEY
  where
    zone = delegationZone
    toDNSKEYs (rrs, _rank) = [rd | rr <- rrs, Just rd <- [DNS.fromRData $ rdata rr]]
    fill dnskeys = pure d{delegationDNSKEY = dnskeys}
    nullIPs = logLn Log.WARN "require-dnskey: address list is null" $> d
    verifyFailed ~es = logLn Log.WARN ("require-dnskey: " ++ es) $> d
    query sas = either verifyFailed fill =<< cachedDNSKEY getSEP sas zone
{- FOURMOLU_ENABLE -}

{-
steps to get verified and cached DNSKEY RRset
1. query DNSKEY from delegatee with DO flag - get DNSKEY RRset and its RRSIG
2. verify SEP DNSKEY of delegatee with DS
3. verify DNSKEY RRset of delegatee with RRSIG
4. cache DNSKEY RRset with RRSIG when validation passes
 -}
cachedDNSKEY
    :: ([ResourceRecord] -> Either String (NonEmpty RD_DNSKEY)) -> [Address] -> Domain -> DNSQuery (Either String [RD_DNSKEY])
cachedDNSKEY getSEPs sas zone = do
    short <- asks shortLog_
    logLn Log.DEMO $ unwords (["require-dnskey: query", show zone, show DNSKEY] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]])
    msg <- norec True sas zone DNSKEY
    let rcode = DNS.rcode msg
    case rcode of
        DNS.NoErr -> withSection rankedAnswer msg $ \srrs _rank ->
            either (pure . Left) (verifyDNSKEY msg) $ getSEPs srrs
        _ -> pure $ Left $ "cachedDNSKEY: error rcode to get DNSKEY: " ++ show rcode
  where
    cachedResult krds dnskeyRRset cacheDNSKEY
        | rrsetValid dnskeyRRset = cacheDNSKEY $> Right krds {- only cache DNSKEY RRset on verification successs -}
        | otherwise = pure $ Left $ "cachedDNSKEY: no verified RRSIG found: " ++ show (rrsMayVerified dnskeyRRset)
    verifyDNSKEY msg (s :| ss) = do
        let dnskeyRD rr = DNS.fromRData $ rdata rr :: Maybe RD_DNSKEY
            {- no DNSKEY case -}
            nullDNSKEY = cacheSectionNegative zone [] zone DNSKEY rankedAnswer msg [] $> Left "cachedDNSKEY: null DNSKEYs"
            ncDNSKEY _ncLog = pure $ Left "cachedDNSKEY: not canonical"
        Verify.cases NoCheckDisabled zone (s : ss) rankedAnswer msg zone DNSKEY dnskeyRD nullDNSKEY ncDNSKEY cachedResult

---

{- FOURMOLU_DISABLE -}
delegationFallbacks
    :: Int -> Bool -> ([Address] -> DNSQuery b)
    -> Delegation -> Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
delegationFallbacks dc dnssecOK ah d0 name typ = do
    disableV6NS <- asks disableV6NS_
    delegationFallbacks_ handled failed qparallel disableV6NS dc dnssecOK ah d0 name typ
  where
    handled = logLn Log.DEMO
    failed ass = logLines Log.DEMO ("delegationFallbacks: failed:" : ["  " ++ unwords (ns : map pprAddr as) | (ns, as) <- ass])
    qparallel = 2
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
delegationFallbacks_
    :: (String -> DNSQuery c)
    -> ([(String, [Address])] -> DNSQuery a)
    -> Int -> Bool -> Int -> Bool -> ([Address] -> DNSQuery b)
    -> Delegation -> Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
delegationFallbacks_ eh fh qparallel disableV6NS dc dnssecOK ah d0@Delegation{..} name typ = do
    paxs1  <- dentryToPermAx disableV6NS dentry
    pnss   <- dentryToPermNS zone dentry
    fallbacks id d0 ("<cached>", \d n j -> list (n d) (\a as -> j d $ a :| as) paxs1) [(show ns, resolveNS' ns) | ns <- pnss]
  where
    dentry = NE.toList delegationNS
    fallbacks aa d (tag, runAxs) runsAxs = runAxs d emp ne
      where
        emp d' = list (fh (aa []) >> throwDnsError ServerFailure) (fallbacks (aa . ((tag, []):)) d') runsAxs
        ne d' paxs = list step (\g gs -> step `catchError` \e -> hlog e >> fallbacks (aa . ((tag, paxs'):)) d' g gs) runsAxs
          where
            step = case [(ah axc >> norec dnssecOK axc name typ) | axc <- chunksOfN qparallel paxs] of
                f:|fs -> (,) <$> catches f fs <*> pure d'
            paxs' = NE.toList paxs
            hlog e = eh' $ unwords $ show e : "for" : map show paxs'
    catches x  []     = x
    catches x (y:xs)  = x `catchError` \_e -> catches y xs

    resolveNS' ns d emp ne = do
        {- tryError idiom, before mtl 2.3 -}
        e <- (Right <$> resolveNS zone disableV6NS dc ns) `catchError` (pure . Left)
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
resolveNS :: Domain -> Bool -> Int -> Domain -> DNSQuery (Either (RCODE, String) (NonEmpty (IP, ResourceRecord)))
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
            pure $ (rcode msg, withSection rankedAnswer msg $ \rrs _rank -> axPairs rrs)

    failEmptyAx rc = do
        let emptyInfo = if disableV6NS then "empty A (disable-v6ns)" else "empty A|AAAA"
        orig <- showQ "orig-query:" <$> asksQP origQuestion_
        let errorInfo = (if rc == NoErr then emptyInfo else show rc) ++ " for NS,"
        pure $ Left (rc, unwords $ errorInfo : ["ns: " ++ show ns ++ ",", "zone: " ++ show zone ++ ",", orig])
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
-- Get authoritative server addresses from the delegation information.
delegationIPs :: Delegation -> DNSQuery [Address]
delegationIPs Delegation{..} = do
    disableV6NS <- asks disableV6NS_
    ips <- dentryToRandomIP entryNum addrNum disableV6NS dentry
    when (null ips) $ throwDnsError DNS.UnknownDNSError  {- assume filled IPs by fillDelegation -}
    pure ips
  where
    dentry = NE.toList delegationNS
    entryNum = 2
    addrNum = 2
{- FOURMOLU_ENABLE -}

maxQueryCount :: Int
maxQueryCount = 64

norec :: Bool -> [Address] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnssecOK aservers name typ = do
    qcount <- (length aservers +) <$> (liftIO =<< asksQS getQueryCount_)
    logLn Log.DEBUG ("query count: " ++ show qcount)
    orig <- showQ "orig-query" <$> asksQP origQuestion_
    m <- dispatch qcount orig
    asksQS setQueryCount_ >>= \setCount -> liftIO $ setCount qcount
    pure m
  where
    dispatch qcount orig
        | qcount > maxQueryCount = logLn Log.WARN (exceeded orig) >> left ServerFailure
        | otherwise = lift (Norec.norec' dnssecOK aservers name typ) >>= either left (handleResponseError aservers throwError pure)
    exceeded orig = "max-query-count (==" ++ show maxQueryCount ++ ") exceeded: " ++ showQ' "query" name typ ++ ", " ++ orig
    left e = cacheDNSError name typ Cache.RankAnswer e >> dnsError e
    dnsError e = throwError $ uncurry DnsError $ unwrapDNSErrorInfo e
