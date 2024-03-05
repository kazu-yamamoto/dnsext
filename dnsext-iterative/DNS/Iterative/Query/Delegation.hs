{-# LANGUAGE DeriveTraversable #-}

module DNS.Iterative.Query.Delegation (
    lookupDelegation,
    delegationWithCache,
    MayDelegation,
    noDelegation,
    hasDelegation,
    mayDelegation,
) where

-- GHC packages
import qualified Data.Set as Set

-- other packages

-- dnsext packages
import qualified DNS.Log as Log
import DNS.RRCache (
    rankedAdditional,
    rankedAuthority,
 )
import qualified DNS.RRCache as Cache
import DNS.SEC
import qualified DNS.SEC.Verify as SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IPv4, IPv6)
import System.Console.ANSI.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
import qualified DNS.Iterative.Query.Verify as Verify

newtype GMayDelegation a
    = MayDelegation (Maybe a)
    deriving (Functor, Foldable, Traversable)

type MayDelegation = GMayDelegation Delegation

noDelegation :: MayDelegation
noDelegation = MayDelegation Nothing

hasDelegation :: Delegation -> MayDelegation
hasDelegation = MayDelegation . Just

mayDelegation :: a -> (Delegation -> a) -> MayDelegation -> a
mayDelegation n h (MayDelegation m) = maybe n h m

{- FOURMOLU_DISABLE -}
-- If Nothing, it is a miss-hit against the cache.
-- If Just NoDelegation, cache hit but no delegation information.
lookupDelegation :: Domain -> ContextT IO (Maybe MayDelegation)
lookupDelegation zone = do
    disableV6NS <- asks disableV6NS_
    let noCachedV4NS es = disableV6NS && all noV4DEntry es

        fromDEs es
            {- all NS records for A are skipped under disableV6NS, so handle as miss-hit NS case -}
            | noCachedV4NS es = Nothing
            --
            {- Nothing case, all NS records are skipped, so handle as miss-hit NS case -}
            | otherwise = list Nothing ((Just .) . hasDelegation') es
          where hasDelegation' de des = hasDelegation $ Delegation zone (de :| des) (NotFilledDS CachedDelegation) [] CachedD

        getDelegation :: ([ResourceRecord], a) -> ContextT IO (Maybe MayDelegation)
        getDelegation (rrs, _) = do
            {- NS cache hit -}
            let nss = sort $ nsList zone const rrs
            case nss of
                []     -> return $ Just noDelegation {- hit null NS list, so no delegation -}
                _ : _  -> fromDEs . concat <$> mapM (lookupDEntry zone) nss

    maybe (return Nothing) getDelegation =<< lookupCache zone NS
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
noV4DEntry :: DEntry -> Bool
noV4DEntry (DEonlyNS {})          = True
noV4DEntry (DEwithA4 _ (_:|_))    = False
noV4DEntry (DEwithA6 _ _)         = True
noV4DEntry (DEwithAx _ (_:|_) _)  = False
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- Caching while retrieving delegation information from the authoritative server's reply
delegationWithCache :: Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> DNSQuery MayDelegation
delegationWithCache zone dnskeys dom msg = do
    {- There is delegation information only when there is a selectable NS -}
    getSec <- lift $ asks currentSeconds_
    maybe (notFound $> noDelegation) (fillDEntries <=< found getSec) $ findDelegation nsps adds
  where
    found getSec k = Verify.cases getSec zone dnskeys rankedAuthority msg dom DS fromDS (nullDS k) ncDS (withDS k)
    fromDS = DNS.fromRData . rdata
    {- TODO: NoData DS negative cache -}
    nullDS k = do
        unsignedDelegationOrNoData $> ()
        lift $ vrfyLog (Just Yellow) "delegation - no DS, so no verification chain"
        lift $ caches $> k []
    ncDS _ncLog = lift (vrfyLog (Just Red) "delegation - not canonical DS") *> throwDnsError DNS.ServerFailure
    withDS k dsrds dsRRset cacheDS
        | rrsetValid dsRRset = lift $ do
            let x = k dsrds
            vrfyLog (Just Green) "delegation - verification success - RRSIG of DS"
            caches *> cacheDS $> x
        | otherwise =
            lift (vrfyLog (Just Red) "delegation - verification failed - RRSIG of DS") *> throwDnsError DNS.ServerFailure
    caches = cacheNS *> cacheAdds

    notFound = lift $ vrfyLog Nothing "no delegation"
    vrfyLog vrfyColor vrfyMsg = clogLn Log.DEMO vrfyColor $ vrfyMsg ++ ": " ++ domTraceMsg
    domTraceMsg = show zone ++ " -> " ++ show dom

    (nsps, cacheNS) = withSection rankedAuthority msg $ \rrs rank ->
        let nsps_ = nsList dom (,) rrs in (nsps_, cacheNoRRSIG (map snd nsps_) rank)

    (adds, cacheAdds) = withSection rankedAdditional msg $ \rrs rank ->
        let axs = filter match rrs in (axs, cacheSection axs rank)
      where
        match rr = rrtype rr `elem` [A, AAAA] && rrname rr `isSubDomainOf` zone && rrname rr `Set.member` nsSet
        nsSet = Set.fromList $ map fst nsps

    unsignedDelegationOrNoData = unsignedDelegationOrNoDataAction zone dnskeys dom A msg
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fillDEntries :: Delegation -> DNSQuery MayDelegation
fillDEntries d = list noAvail result =<< lift (concat <$> mapM fill des)
  where
    des = delegationNS d
    fill (DEonlyNS ns) = lookupDEntry (delegationZone d) ns
    fill  e            = pure [e]
    noAvail = lift (logLines Log.DEMO ("fillDEntries - no NS available: " : pprNS des)) *> throwDnsError DNS.ServerFailure
    pprNS (e:|es) = map (("  " ++) . show) $ e : es
    result e es = pure $ hasDelegation d{delegationNS = e :| es}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
lookupDEntry :: Domain -> Domain -> ContextT IO [DEntry]
lookupDEntry zone ns = do
    withNX =<< lookupCache ns Cache.NX
  where
    withNX Just{}   = pure []
    withNX Nothing  = do
        let takeV4 = rrListWith A    (`DNS.rdataField` DNS.a_ipv4)    ns const
            takeV6 = rrListWith AAAA (`DNS.rdataField` DNS.aaaa_ipv6) ns const
        lk4 <- fmap (takeV4 . fst) <$> lookupCache ns A
        lk6 <- fmap (takeV6 . fst) <$> lookupCache ns AAAA
        pure $ dentryFromCache zone ns lk4 lk6
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- | result value cases of dentryFromCache :
--     []             : miss-hit, skip this NS name, to avoid iterative loop
--     [DEonlyNS {}]  : miss-hit
--     [DEwithA...]   : hit
--
-- >>> :seti -XOverloadedStrings
-- >>> dentryFromCache "example." "ns.example." Nothing Nothing
-- []
-- >>> dentryFromCache "example." "ns.example." Nothing (Just [])
-- []
-- >>> dentryFromCache "example." "ns.example." (Just []) Nothing
-- []
-- >>> dentryFromCache "example." "ns.example." (Just []) (Just [])
-- []
-- >>> dentryFromCache "a.example." "ns.example." Nothing Nothing
-- [DEonlyNS "ns.example."]
-- >>> dentryFromCache "a.example." "ns.example." Nothing (Just [])
-- [DEonlyNS "ns.example."]
-- >>> dentryFromCache "a.example." "ns.example." (Just []) Nothing
-- [DEonlyNS "ns.example."]
-- >>> dentryFromCache "a.example." "ns.example." (Just []) (Just [])
-- []
-- >>> dentryFromCache "a.example." "ns.example." (Just ["192.0.2.1"]) (Just [])
-- [DEwithA4 "ns.example." (192.0.2.1 :| [])]
-- >>> dentryFromCache "a.example." "ns.example." (Just []) (Just ["2001:db8::1"])
-- [DEwithA6 "ns.example." (2001:db8::1 :| [])]
-- >>> dentryFromCache "a.example." "ns.example." (Just ["192.0.2.1"]) (Just ["2001:db8::1"])
-- [DEwithAx "ns.example." (192.0.2.1 :| []) (2001:db8::1 :| [])]
dentryFromCache :: Domain -> Domain -> Maybe [IPv4] -> Maybe [IPv6] -> [DEntry]
dentryFromCache zone ns = dispatch
  where
    missHit
        | ns `DNS.isSubDomainOf` zone  = []  {- miss-hit with sub-domain case cause iterative loop. null result to skip this NS -}
        | otherwise                    = [DEonlyNS ns]
    dispatch Nothing       Nothing          = missHit  {- A: miss-hit     AAAA: miss-hit                       -}
    dispatch Nothing       (Just [])        = missHit  {- A: miss-hit     AAAA: hit NoData  , assumes miss-hit -}
    dispatch (Just [])     Nothing          = missHit  {- A: hit NoData   AAAA: miss-hit    , assumes miss-hit -}
    dispatch Nothing       (Just (i:is))    = [DEwithA6 ns (i :| is)]
    dispatch (Just (i:is)) Nothing          = [DEwithA4 ns (i :| is)]
    dispatch (Just i4s)   (Just i6s)        = foldIPList'
                                              []       {- A: hit NoData   AAAA: hit NoData  , maybe wrong cache, skip this NS -}
                                              (\v4    -> [DEwithA4 ns v4])
                                              (\v6    -> [DEwithA6 ns v6])
                                              (\v4 v6 -> [DEwithAx ns v4 v6])
                                              i4s i6s
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
unsignedDelegationOrNoDataAction
    :: Domain -> [RD_DNSKEY]
    -> Domain -> TYPE -> DNSMessage
    -> DNSQuery [RRset]
unsignedDelegationOrNoDataAction zone dnskeys qname_ qtype_ msg = join $ lift nsec
  where
    nsec  = Verify.nsecWithValid   dnskeys rankedAuthority msg nullNSEC invalidK nsecK
    nullNSEC = nsec3
    nsecK  ranges rrsets doCache =
        Verify.runHandlers "cannot handle NSEC UnsignedDelegation/NoDatas:"  noWitnessK $
        handle unsignedDelegation resultK .
        handle wildcardNoData     resultK .
        handle noData             resultK
      where
        handle = Verify.mkHandler ranges rrsets doCache
        unsignedDelegation rs  = SEC.unsignedDelegationNSEC   zone rs qname_
        wildcardNoData     rs  = SEC.wildcardNoDataNSEC       zone rs qname_ qtype_
        noData             rs  = SEC.noDataNSEC               zone rs qname_ qtype_

    nsec3 = Verify.nsec3WithValid  dnskeys rankedAuthority msg nullK    invalidK nsec3K
    nsec3K ranges rrsets doCache =
        Verify.runHandlers "cannot handle NSEC3 UnsignedDelegation/NoDatas:" noWitnessK $
        handle unsignedDelegation resultK .
        handle wildcardNoData     resultK .
        handle noData             resultK
      where
        handle = Verify.mkHandler ranges rrsets doCache
        unsignedDelegation rs  = SEC.unsignedDelegationNSEC3  zone rs qname_
        wildcardNoData     rs  = SEC.wildcardNoDataNSEC3      zone rs qname_ qtype_
        noData             rs  = SEC.noDataNSEC3              zone rs qname_ qtype_

    nullK = pure $ noverify "no NSEC/NSEC3 records" $> []
    invalidK s = failed $ "invalid NSEC/NSEC3: " ++ traceInfo ++ " : " ++ s
    noWitnessK s = pure $ noverify ("nsec witness not found: " ++ traceInfo ++ " : " ++ s) $> []
    resultK w rrsets _ = pure $ success w $> rrsets

    success w = putLog (Just Green) $ "nsec verification success - " ++ witnessInfo w
    noverify s = putLog (Just Yellow) $ "nsec no verification - " ++ s
    failed s = pure $ putLog (Just Red) ( "nsec verification failed - " ++ s) *> throwDnsError DNS.ServerFailure

    putLog color s = lift $ clogLn Log.DEMO color s

    witnessInfo w = SEC.witnessName w ++ ": " ++ SEC.witnessDelegation w traceInfo qinfo
    traceInfo = show zone ++ " -> " ++ show qname_
    qinfo = show qname_ ++ " " ++ show qtype_
{- FOURMOLU_ENABLE -}
