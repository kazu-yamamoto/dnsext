{-# LANGUAGE FlexibleContexts #-}
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
) where

-- GHC packages
import qualified Data.List.NonEmpty as NE

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
import DNS.Iterative.Query.TrustAnchor
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
                      pure msg
                | otherwise                     = request nss
        (,) <$> maybe (request nss) reuseMsg mmsg <*> pure nss
  where
    mdc = maxNotSublevelDelegation
    getAnchor = do
        stub <- asks stubZones_
        maybe refreshRoot pure $ Stub.lookupStub stub n
    request nss@Delegation{..} = do
        checkEnabled <- getCheckEnabled
        sas <- delegationIPs nss
        short <- asks shortLog_
        logLn Log.DEMO $ unwords (["resolve-exact: query", show n, show typ] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]])
        let withDO = checkEnabled && chainedStateDS nss && not (null delegationDNSKEY)
        norec withDO sas n typ
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
        sas <- delegationIPs nss
        short <- asks shortLog_
        logLn Log.DEMO $ unwords (["iterative: query", show name, show A] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]])
        let withDO = checkEnabled && chainedStateDS nss && not (null delegationDNSKEY)
        {- Use `A` for iterative queries to the authoritative servers during iterative resolution.
           See the following document:
           QNAME Minimisation Examples: https://datatracker.ietf.org/doc/html/rfc9156#section-4 -}
        msg <- norec withDO sas name requestDelegationTYPE
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
            let axsDE = foldIPnonEmpty (DEwithA4 name) (DEwithA6 name) (DEwithAx name)
            filled <- axsDE . fmap fst <$> resolveNS zone disableV6NS dc name
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

{- FOURMOLU_DISABLE -}
resolveNS :: Domain -> Bool -> Int -> Domain -> DNSQuery (NonEmpty (IP, ResourceRecord))
resolveNS zone disableV6NS dc ns = do
    axs <- query1Ax
    list failEmptyAx (\a as -> pure $ a :| as) axs
  where
    axPairs = axList disableV6NS (== ns) (,)

    query1Ax
        | disableV6NS = querySection A
        | otherwise = join $ randomizedChoice q46 q64
      where
        q46 = A +!? AAAA
        q64 = AAAA +!? A
        tx +!? ty = do
            xs <- querySection tx
            if null xs then querySection ty else pure xs
        querySection typ = do
            logLn Log.DEMO $ unwords ["resolveNS:", show (ns, typ), "dc:" ++ show dc, "->", show (succ dc)]
            {- resolve for not sub-level delegation. increase dc (delegation count) -}
            cacheAnswerAx typ =<< resolveExactDC (succ dc) ns typ
        cacheAnswerAx typ (msg, d) = do
            cacheAnswer d ns typ msg $> ()
            pure $ withSection rankedAnswer msg $ \rrs _rank -> axPairs rrs

    failEmptyAx = do
        let emptyInfo
                | disableV6NS  = "empty A (disable-v6ns): "
                | otherwise    = "empty A|AAAA: "
        orig <- showQ "orig-query:" <$> asksQP origQuestion_
        logLn Log.WARN $ unwords [ "resolveNS: serv-fail,", (emptyInfo ++ show ns ++ ","), ("zone: " ++ show zone ++ ","), orig ]
        throwDnsError ServerFailure
{- FOURMOLU_ENABLE -}
