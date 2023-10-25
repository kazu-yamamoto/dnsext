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
import Data.IORef (newIORef)
import Data.List.NonEmpty (nonEmpty)
import System.Timeout (timeout)

-- other packages
import Data.IP (IP)
import System.Console.ANSI.Types

-- dnsext packages
import DNS.Do53.Client (QueryControls (..))
import DNS.Do53.Internal (newConcurrentGenId)
import qualified DNS.Log as Log
import DNS.RRCache (
    rankedAnswer,
    rankedAuthority,
 )
import qualified DNS.RRCache as Cache
import DNS.SEC
import DNS.TimeCache (TimeCache (..), noneTimeCache)
import DNS.Types
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Delegation
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Norec
import DNS.Iterative.Query.Random
import DNS.Iterative.Query.Root
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
import qualified DNS.Iterative.Query.Verify as Verify
import DNS.Iterative.Stats

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
runResolveExact cxt n typ cd = runDNSQuery (resolveExact n typ) cxt cd

{-# DEPRECATED resolveJust "use resolveExact instead of this" #-}
resolveJust :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJust = resolveExact

-- 反復検索を使って最終的な権威サーバーからの DNSMessage とその委任情報を得る. CNAME は解決しない.
resolveExact :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveExact = resolveExactDC 0

resolveExactDC :: Int -> Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveExactDC dc n typ
    | dc > mdc = do
        lift . logLn Log.WARN $ "resolve-exact: not sub-level delegation limit exceeded: " ++ show (n, typ)
        throwDnsError DNS.ServerFailure
    | otherwise = do
        root <- refreshRoot
        nss@Delegation{..} <- iterative_ dc root $ DNS.superDomains n
        sas <- delegationIPs dc nss
        lift . logLn Log.DEMO $ unwords (["resolve-exact: query", show (n, typ), "servers:"] ++ [show sa | sa <- sas])
        let dnssecOK = delegationHasDS nss && not (null delegationDNSKEY)
        (,) <$> norec dnssecOK sas n typ <*> pure nss
  where
    mdc = maxNotSublevelDelegation

-- Filter authoritative server addresses from the delegation information.
-- If the resolution result is NODATA, IllegalDomain is returned.
delegationIPs :: Int -> Delegation -> DNSQuery [IP]
delegationIPs dc Delegation{..} = do
    disableV6NS <- lift $ asks disableV6NS_

    let ipnum = 4
        ips = takeDEntryIPs disableV6NS delegationNS
        zone = delegationZone

        takeNames (DEonlyNS name) xs
            | not (name `DNS.isSubDomainOf` zone) = name : xs
        --    {- skip sub-domain without glue to avoid loop -}
        takeNames _ xs = xs

        names = foldr takeNames [] delegationNS

        result
            | not (null ips) = selectIPs ipnum ips
            | Just names1 <- nonEmpty names = do
                {- case for not (null names) -}
                name <- randomizedSelectN names1
                (: []) . fst <$> resolveNS disableV6NS dc name
            | disableV6NS && not (null allIPs) = do
                plogLn Log.DEMO $ "delegationIPs: server-fail: domain: " ++ show zone ++ ", delegation is empty."
                throwDnsError DNS.ServerFailure
            | otherwise = do
                plogLn Log.DEMO $ "illegal-domain: " ++ show zone ++ ", delegation is empty. without glue sub-domains: " ++ show subNames
                throwDnsError DNS.IllegalDomain
          where
            allIPs = takeDEntryIPs False delegationNS
            plogLn lv = lift . logLn lv . ("delegationIPs: " ++)

        takeSubNames (DEonlyNS name) xs
            | name `DNS.isSubDomainOf` zone =
                name : xs {- sub-domain name without glue -}
        takeSubNames _ xs = xs
        subNames = foldr takeSubNames [] delegationNS

    result

resolveNS :: Bool -> Int -> Domain -> DNSQuery (IP, ResourceRecord)
resolveNS disableV6NS dc ns = do
    let axPairs = axList disableV6NS (== ns) (,)

        lookupAx
            | disableV6NS = lk4
            | otherwise = join $ randomizedSelectN (lk46 :| [lk64])
          where
            lk46 = lk4 +? lk6
            lk64 = lk6 +? lk4
            lk4 = lookupCache ns A
            lk6 = lookupCache ns AAAA
            lx +? ly = maybe ly (return . Just) =<< lx

        query1Ax
            | disableV6NS = querySection A
            | otherwise = join $ randomizedSelectN (q46 :| [q64])
          where
            q46 = A +!? AAAA
            q64 = AAAA +!? A
            tx +!? ty = do
                xs <- querySection tx
                if null xs then querySection ty else pure xs
            querySection typ = do
                lift . logLn Log.DEMO $ unwords ["resolveNS:", show (ns, typ), "dc:" ++ show dc, "->", show (succ dc)]
                {- resolve for not sub-level delegation. increase dc (delegation count) -}
                lift . cacheAnswerAx =<< resolveExactDC (succ dc) ns typ

            cacheAnswerAx (msg, _) = withSection rankedAnswer msg $ \rrs rank -> do
                let ps = axPairs rrs
                cacheSection (map snd ps) rank
                return ps

        resolveAXofNS :: DNSQuery (IP, ResourceRecord)
        resolveAXofNS = do
            let failEmptyAx
                    | disableV6NS = do
                        lift . logLn Log.WARN $ "resolveNS: server-fail: NS: " ++ show ns ++ ", address is empty."
                        throwDnsError DNS.ServerFailure
                    | otherwise = do
                        lift . logLn Log.WARN $ "resolveNS: illegal-domain: NS: " ++ show ns ++ ", address is empty."
                        throwDnsError DNS.IllegalDomain
            maybe failEmptyAx pure
                =<< randomizedSelect {- 失敗時: NS に対応する A の返答が空 -}
                =<< maybe query1Ax (pure . axPairs . fst)
                =<< lift lookupAx

    resolveAXofNS

fillDelegationDNSKEY :: Int -> Delegation -> DNSQuery Delegation
fillDelegationDNSKEY _ d@Delegation{delegationZone = zone, delegationDS = NotFilledDS o} = do
    {- DS(Delegation Signer) is not filled -}
    lift $ logLn Log.WARN $ "fillDelegationDNSKEY: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show zone
    return d
fillDelegationDNSKEY _ d@Delegation{delegationDS = FilledDS []} = return d {- DS(Delegation Signer) does not exist -}
fillDelegationDNSKEY _ d@Delegation{delegationDS = FilledDS (_ : _), delegationDNSKEY = _ : _} = return d
fillDelegationDNSKEY dc d@Delegation{delegationDS = FilledDS dss@(_ : _), delegationDNSKEY = [], ..} =
    maybe (list1 nullIPs query =<< delegationIPs dc d) (lift . fill . toDNSKEYs) =<< lift (lookupValid zone DNSKEY)
  where
    zone = delegationZone
    toDNSKEYs (rrset, _rank) = [rd | rd0 <- rrsRDatas rrset, Just rd <- [DNS.fromRData rd0]]
    fill dnskeys = return d{delegationDNSKEY = dnskeys}
    nullIPs = lift $ logLn Log.WARN "fillDelegationDNSKEY: ip list is null" *> return d
    verifyFailed ~es = lift (logLn Log.WARN $ "fillDelegationDNSKEY: " ++ es) *> throwDnsError DNS.ServerFailure
    query ips = do
        lift $ logLn Log.DEMO . unwords $ ["fillDelegationDNSKEY: query", show (zone, DNSKEY), "servers:"] ++ [show ip | ip <- ips]
        either verifyFailed (lift . fill) =<< cachedDNSKEY dss ips zone

-- 反復後の委任情報を得る
runIterative
    :: Env
    -> Delegation
    -> Domain
    -> QueryControls
    -> IO (Either QueryError Delegation)
runIterative cxt sa n cd = runDNSQuery (iterative sa n) cxt cd

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
_newTestEnv putLines =
    env <$> newIORef Nothing <*> newConcurrentGenId <*> newStats
  where
    (ins, getCache, expire) = (\_ _ _ _ -> pure (), pure $ Cache.empty 0, const $ pure ())
    TimeCache{..} = noneTimeCache
    env rootRef genId stats =
        Env
            { logLines_ = \_ ~_ -> putLines
            , logDNSTAP_ = \ ~_ -> return ()
            , disableV6NS_ = True
            , insert_ = ins
            , getCache_ = getCache
            , expireCache_ = expire
            , currentRoot_ = rootRef
            , currentSeconds_ = getTime
            , timeString_ = getTimeStr
            , idGen_ = genId
            , stats_ = stats
            , timeout_ = timeout 3000000
            }

_findConsumed :: [String] -> IO ()
_findConsumed ss
    | any ("consumes not-filled DS:" `isInfixOf`) ss = putStrLn "consume message found"
    | otherwise = pure ()

_noLogging :: [String] -> IO ()
_noLogging = const $ pure ()

-- | 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威サーバー群を見つける
--
-- >>> testIterative dom = do { root <- refreshRoot; iterative root dom }
-- >>> env <- _newTestEnv _findConsumed
-- >>> runDNSQuery (testIterative "mew.org.") env mempty $> ()  {- fill-action is not called -}
--
-- >>> runDNSQuery (testIterative "arpa.") env mempty $> ()  {- fill-action is called for `ServsChildZone` -}
-- consume message found
iterative :: Delegation -> Domain -> DNSQuery Delegation
iterative sa n = iterative_ 0 sa $ DNS.superDomains n

iterative_ :: Int -> Delegation -> [Domain] -> DNSQuery Delegation
iterative_ _ nss0 [] = return nss0
iterative_ dc nss0 (x : xs) =
    {- If NS is not returned, the information of the same NS is used for the child domain. or.jp and ad.jp are examples of this case. -}
    step nss0 >>= mayDelegation (recurse nss0 xs) (`recurse` xs)
  where
    recurse = iterative_ dc {- sub-level delegation. increase dc only not sub-level case. -}
    name = x

    lookupNX :: ContextT IO Bool
    lookupNX = isJust <$> lookupCache name Cache.NX

    stepQuery :: Delegation -> DNSQuery MayDelegation
    stepQuery nss@Delegation{..} = do
        let zone = delegationZone
            dnskeys = delegationDNSKEY
        {- When the same NS information is inherited from the parent domain, balancing is performed by re-selecting the NS address. -}
        sas <- delegationIPs dc nss
        lift . logLn Log.DEMO $ unwords (["iterative: query", show (name, A), "servers:"] ++ [show sa | sa <- sas])
        let dnssecOK = delegationHasDS nss && not (null delegationDNSKEY)
        {- Use `A` for iterative queries to the authoritative servers during iterative resolution.
           See the following document:
           QNAME Minimisation Examples: https://datatracker.ietf.org/doc/html/rfc9156#section-4 -}
        msg <- norec dnssecOK sas name A
        let withNoDelegation handler = mayDelegation handler (return . hasDelegation)
            sharedHandler = servsChildZone dc nss name msg
            cacheHandler = cacheNoDelegation nss zone dnskeys name msg $> noDelegation
            logFound d = lift (logDelegation d) $> hasDelegation d
        delegationWithCache zone dnskeys name msg
            >>= withNoDelegation sharedHandler
            >>= withNoDelegation cacheHandler
            >>= mayDelegation (pure noDelegation) logFound
    logDelegation Delegation{..} = do
        let zplogLn lv = logLn lv . (("zone: " ++ show delegationZone ++ ":\n") ++)
        putDelegation PPFull delegationNS (zplogLn Log.DEMO) (zplogLn Log.DEBUG)

    step :: Delegation -> DNSQuery MayDelegation
    step nss@Delegation{..} = do
        let withNXC nxc
                | nxc = pure noDelegation
                | otherwise = stepQuery nss
            getDelegation FreshD = stepQuery nss {- refresh for fresh parent -}
            getDelegation CachedD = lift (lookupDelegation name) >>= maybe (lift lookupNX >>= withNXC) pure
        getDelegation delegationFresh >>= mapM (fillsDNSSEC dc nss)

maxNotSublevelDelegation :: Int
maxNotSublevelDelegation = 16

{- Workaround delegation for one authoritative server has both domain zone and sub-domain zone -}
servsChildZone :: Int -> Delegation -> Domain -> DNSMessage -> DNSQuery MayDelegation
servsChildZone dc nss dom msg =
    handleSOA (pure noDelegation)
  where
    handleSOA fallback = withSection rankedAuthority msg $ \srrs _rank -> do
        let soaRRs = rrListWith SOA soaRD dom (\_ rr -> rr) srrs
        case soaRRs of
            [] -> fallback
            {- When `A` records are found, indistinguishable from the A definition without sub-domain cohabitation -}
            [_] -> getWorkaround >>= verifySOA
            _ : _ : _ -> multipleSOA soaRRs
      where
        soaRD rd = DNS.fromRData rd :: Maybe DNS.RD_SOA
        multipleSOA soaRRs = do
            lift . logLn Log.WARN $ "servsChildZone: " ++ show dom ++ ": multiple SOAs are found:"
            lift . logLn Log.DEMO $ show dom ++ ": multiple SOA: " ++ show soaRRs
            throwDnsError DNS.ServerFailure
        verifySOA wd
            | null dnskeys = pure $ hasDelegation wd
            | otherwise = Verify.with dnskeys rankedAuthority msg dom SOA (soaRD . rdata) nullSOA ncSOA result
          where
            dnskeys = delegationDNSKEY wd
            nullSOA = pure noDelegation {- guarded by soaRRs [] case -}
            ncSOA = pure noDelegation {- guarded by soaRRs [_] case. single record must be canonical -}
            result _ soaRRset _cacheSOA
                | rrsetValid soaRRset = pure $ hasDelegation wd
                | otherwise = verificationError
    verificationError = do
        lift . logLn Log.WARN $ "servsChildZone: " ++ show dom ++ ": verification error. invalid SOA:"
        lift . clogLn Log.DEMO (Just Red) $ show dom ++ ": verification error. invalid SOA"
        throwDnsError DNS.ServerFailure
    getWorkaround = fillsDNSSEC dc nss (Delegation dom (delegationNS nss) (NotFilledDS ServsChildZone) [] (delegationFresh nss))

fillsDNSSEC :: Int -> Delegation -> Delegation -> DNSQuery Delegation
fillsDNSSEC dc nss d = do
    filled@Delegation{..} <- fillDelegationDNSKEY dc =<< fillDelegationDS dc nss d
    when (delegationHasDS filled && null delegationDNSKEY) $ do
        let zone = show delegationZone
        lift . logLn Log.WARN $ "fillsDNSSEC: " ++ zone ++ ": DS is not null, and DNSKEY is null"
        lift . clogLn Log.DEMO (Just Red) $ zone ++ ": verification error. dangling DS chain. DS exists, and DNSKEY does not exists"
        throwDnsError DNS.ServerFailure
    return filled

-- | Fill DS for delegation info. The result must be `FilledDS` for success query.
--
-- >>> Right dummyKey = Opaque.fromBase64 "dummykey///dummykey///dummykey///dummykey///"
-- >>> dummyDNSKEY = RD_DNSKEY [ZONE] 3 RSASHA256 $ toPubKey RSASHA256 dummyKey
-- >>> Right dummyDS_ = Opaque.fromBase16 "0123456789ABCD0123456789ABCD0123456789ABCD0123456789ABCD"
-- >>> dummyDS = RD_DS 0 RSASHA256 SHA256 dummyDS_
-- >>> withNS2 dom h1 a1 h2 a2 ds = Delegation dom (DEwithAx h1 a1 :| [DEwithAx h2 a2]) ds [dummyDNSKEY] FreshD
-- >>> parent = withNS2 "org." "a0.org.afilias-nst.info." "199.19.56.1" "a2.org.afilias-nst.info." "199.249.112.1" (FilledDS [dummyDS])
-- >>> mkChild ds = withNS2 "mew.org." "ns1.mew.org." "202.238.220.92" "ns2.mew.org." "210.155.141.200" ds
-- >>> isFilled d = case (delegationDS d) of { NotFilledDS _ -> False; FilledDS _ -> True }
-- >>> env <- _newTestEnv _noLogging
-- >>> runChild child = runDNSQuery (fillDelegationDS 0 parent child) env mempty
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS CachedDelegation)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ NotFilledDS ServsChildZone)
-- Right True
-- >>> fmap isFilled <$> (runChild $ mkChild $ FilledDS [])
-- Right True
fillDelegationDS :: Int -> Delegation -> Delegation -> DNSQuery Delegation
fillDelegationDS dc src dest
    | null $ delegationDNSKEY src = fill [] {- no src DNSKEY, not chained -}
    | NotFilledDS o <- delegationDS src = do
        lift $ logLn Log.WARN $ "fillDelegationDS: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show (delegationZone src)
        return dest
    | FilledDS [] <- delegationDS src = fill [] {- no src DS, not chained -}
    | Delegation{..} <- dest = case delegationDS of
        FilledDS _ -> pure dest {- no DS or exist DS, anyway filled DS -}
        NotFilledDS o -> do
            lift $ logLn Log.DEMO $ "fillDelegationDS: consumes not-filled DS: case=" ++ show o ++ " zone: " ++ show delegationZone
            maybe (list1 nullIPs query =<< delegationIPs dc src) (lift . fill . toDSs) =<< lift (lookupValid delegationZone DS)
  where
    toDSs (rrset, _rank) = [rd | rd0 <- rrsRDatas rrset, Just rd <- [DNS.fromRData rd0]]
    fill dss = return dest{delegationDS = FilledDS dss}
    nullIPs = lift $ logLn Log.WARN "fillDelegationDS: ip list is null" *> return dest
    verifyFailed ~es = lift (logLn Log.WARN $ "fillDelegationDS: " ++ es) *> throwDnsError DNS.ServerFailure
    query ips = do
        let zone = delegationZone dest
            result (e, ~verifyColor, ~verifyMsg) = do
                let domTraceMsg = show (delegationZone src) ++ " -> " ++ show zone
                lift . clogLn Log.DEMO (Just verifyColor) $ "fill delegation - " ++ verifyMsg ++ ": " ++ domTraceMsg
                either verifyFailed fill e
        lift $ logLn Log.DEMO . unwords $ ["fillDelegationDS: query", show (zone, DS), "servers:"] ++ [show ip | ip <- ips]
        result =<< queryDS (delegationDNSKEY src) ips zone

queryDS
    :: [RD_DNSKEY]
    -> [IP]
    -> Domain
    -> DNSQuery (Either String [RD_DS], Color, String)
queryDS dnskeys ips dom = do
    msg <- norec True ips dom DS
    Verify.with dnskeys rankedAnswer msg dom DS (DNS.fromRData . rdata) nullDS ncDS verifyResult
  where
    nullDS = pure (Right [], Yellow, "no DS, so no verify")
    ncDS = pure (Left "queryDS: not canonical DS", Red, "not canonical DS")
    verifyResult dsrds dsRRset cacheDS
        | rrsetValid dsRRset = lift cacheDS $> (Right dsrds, Green, "verification success - RRSIG of DS")
        | otherwise = pure (Left "queryDS: verification failed - RRSIG of DS", Red, "verification failed - RRSIG of DS")
