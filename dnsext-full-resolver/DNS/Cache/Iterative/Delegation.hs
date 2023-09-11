{-# LANGUAGE DeriveTraversable #-}

module DNS.Cache.Iterative.Delegation (
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
import DNS.Do53.Memo (
    rankedAdditional,
    rankedAuthority,
 )
import qualified DNS.Log as Log
import DNS.SEC
import qualified DNS.SEC.Verify as SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))
import System.Console.ANSI.Types

-- this package
import DNS.Cache.Imports
import DNS.Cache.Iterative.Cache
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Cache.Iterative.Verify as Verify

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

-- If Nothing, it is a miss-hit against the cache.
-- If Just NoDelegation, cache hit but no delegation information.
lookupDelegation :: Domain -> ContextT IO (Maybe MayDelegation)
lookupDelegation dom = do
    disableV6NS <- asks disableV6NS_
    let lookupDEs ns = do
            let deListA = rrListWith A (`DNS.rdataField` DNS.a_ipv4) ns (\v4 _ -> DEwithAx ns (IPv4 v4))
                deListAAAA = rrListWith AAAA (`DNS.rdataField` DNS.aaaa_ipv6) ns (\v6 _ -> DEwithAx ns (IPv6 v6))

            lk4 <- fmap (deListA . fst) <$> lookupCache ns A
            lk6 <- fmap (deListAAAA . fst) <$> lookupCache ns AAAA
            return $ case lk4 <> lk6 of
                Nothing
                    | ns `DNS.isSubDomainOf` dom -> [] {- miss-hit with sub-domain case cause iterative loop, so return null to skip this NS -}
                    | otherwise -> [DEonlyNS ns {- the case both A and AAAA are miss-hit -}]
                Just as -> as {- just return address records. null case is wrong cache, so return null to skip this NS -}
        noCachedV4NS es = disableV6NS && null (v4DEntryList es)

        fromDEs es
            {- all NS records for A are skipped under disableV6NS, so handle as miss-hit NS case -}
            | noCachedV4NS es = Nothing
            --
            {- Nothing case, all NS records are skipped, so handle as miss-hit NS case -}
            | otherwise = (\des -> hasDelegation $ Delegation dom des (NotFilledDS CachedDelegation) []) <$> uncons es

        getDelegation :: ([ResourceRecord], a) -> ContextT IO (Maybe MayDelegation)
        getDelegation (rrs, _) = do
            {- NS cache hit -}
            let nss = sort $ nsList dom const rrs
            case nss of
                [] -> return $ Just noDelegation {- hit null NS list, so no delegation -}
                _ : _ -> fromDEs . concat <$> mapM lookupDEs nss

    maybe (return Nothing) getDelegation =<< lookupCache dom NS

v4DEntryList :: [DEntry] -> [DEntry]
v4DEntryList [] = []
v4DEntryList des@(de : _) = concatMap skipAAAA $ byNS des
  where
    byNS = groupBy ((==) `on` nsDomain)
    skipAAAA = nullCase . filter (not . aaaaDE)
      where
        aaaaDE (DEwithAx _ (IPv6{})) = True
        aaaaDE _ = False
        nullCase [] = [DEonlyNS (nsDomain de)]
        nullCase es@(_ : _) = es

nsDomain :: DEntry -> Domain
nsDomain (DEwithAx dom _) = dom
nsDomain (DEonlyNS dom) = dom

-- Caching while retrieving delegation information from the authoritative server's reply
delegationWithCache :: Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> DNSQuery MayDelegation
delegationWithCache zone dnskeys dom msg = do
    {- There is delegation information only when there is a selectable NS -}
    maybe (notFound $> noDelegation) (fmap hasDelegation . found) $ findDelegation nsps adds
  where
    found k = Verify.with dnskeys rankedAuthority msg dom DS fromDS (nullDS k) (ncDS k) (withDS k)
    fromDS = DNS.fromRData . rdata
    {- TODO: NoData DS negative cache -}
    nullDS k = do
        unsignedDelegationOrNoData $> ()
        lift $ vrfyLog (Just Yellow) "delegation - no DS, so no verification chain"
        lift $ caches $> k []
    ncDS _ = lift (vrfyLog (Just Red) "delegation - not canonical DS") *> throwDnsError DNS.ServerFailure
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
