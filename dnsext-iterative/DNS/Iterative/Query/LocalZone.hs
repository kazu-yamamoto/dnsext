module DNS.Iterative.Query.LocalZone where

-- GHC packages
import Data.Map (Map)
import qualified Data.Map.Strict as Map

-- other packages

-- dnsext packages

import DNS.SEC.Verify (canonicalRRset)
import DNS.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.ZoneMap

-- $setup
-- >>> :seti -Wno-orphans
-- >>> :seti -XStandaloneDeriving
-- >>> deriving instance Eq RRset
-- >>> :seti -XOverloadedStrings
-- >>> rrset dom typ rds = RRset dom typ IN 3600 rds notValidNoSig
-- >>> kvp dom ps = (dom, [rrset dom typ rds | (typ, rds) <- ps ])
-- >>> kvp1 dom typ rds = kvp dom [(typ, rds)]

{- FOURMOLU_DISABLE -}
nameMap :: [(Domain, LocalZoneType, [ResourceRecord])] -> Map Domain [RRset]
nameMap lzones =
    Map.fromList $ concatMap (byName . zoneRRsets) lzones
  where
    rrKey = (,,) <$> rrname <*> rrtype <*> rrclass
    withName []            = error "newEnv.withName: group must not be null!"
    withName rrss@(rrs:_)  = (rrsName rrs, rrss)
    getRRset rrs = canonicalRRset rrs (const Nothing) (\n t c ttl rds -> Just $ RRset n t c ttl rds notValidNoSig)
    zoneRRsets (_d, _zt, rrs) = mapMaybe getRRset $ groupBy ((==) `on` rrKey) $ sortOn rrKey rrs
    byName = map withName . groupBy ((==) `on` rrsName)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- |
-- >>> lookupName' (Map.fromList []) (Question "a.example." A IN) "n" (const "j") :: String
-- "n"
-- >>> lookupName' (Map.fromList [ kvp "a.example" [(A, [rd_a "203.0.113.7"]), (AAAA, [rd_aaaa "2001:db8::7"])] ]) (Question "a.example." A IN) [] (concatMap rrsRDatas)
-- [203.0.113.7]
lookupName' :: Map Domain [RRset] -> Question -> a -> ([RRset] -> a) -> a
lookupName' nMap (Question dom typ cls) nothing just = maybe nothing (just . result) $ Map.lookup dom nMap
  where
    result rss = [ rs | rs <- rss, rrsType rs == typ, rrsClass rs == cls ]
{- FOURMOLU_ENABLE -}

lzDomain :: (Domain, LocalZoneType, [RRset]) -> Domain
lzDomain (d, _, _) = d

apexMap :: Map Domain [RRset] -> [(Domain, LocalZoneType, [ResourceRecord])] -> Map Domain [(Domain, LocalZoneType, [RRset])]
apexMap nMap lzones = Map.fromList $ subdomainSemilatticeOn lzDomain withSOA
  where
    withSOA = [(d, t, lookupName' nMap (Question d SOA IN) [] id) | (d, t, _) <- lzones]

lookupApex :: Map Domain [(Domain, LocalZoneType, [RRset])] -> Domain -> Maybe (Domain, LocalZoneType, [RRset])
lookupApex = lookupApexOn lzDomain

{- FOURMOLU_DISABLE -}
-- |
-- >>> lk xs apex dom typ = lookupName (Map.fromList xs) apex (Question dom typ IN)
-- >>> soa = rrset "example." SOA [rd_soa "s.example." "root@example." 1 10800 3600 1080000 1800]
-- >>> lk [kvp1 "a.example." A [rd_a "203.0.113.7"]] ("example.", LZ_Deny,   [soa]) "a.example." TXT
-- Nothing
-- >>> lk [kvp1 "a.example." A [rd_a "203.0.113.7"]] ("example.", LZ_Deny,   [soa]) "x.example." A
-- Nothing
-- >>> lk [kvp1 "a.example." A [rd_a "203.0.113.7"]] ("example.", LZ_Refuse, [soa]) "a.example." TXT == Just (Refused, [], [soa])
-- True
-- >>> lk [kvp1 "a.example." A [rd_a "203.0.113.7"]] ("example.", LZ_Refuse, [soa]) "x.example." A   == Just (Refused, [], [soa])
-- True
-- >>> lk [kvp1 "a.example." A [rd_a "203.0.113.7"]] ("example.", LZ_Static, [soa]) "a.example." A   == Just (NoErr, [rrset "a.example." A [rd_a "203.0.113.7"]], [])
-- True
-- >>> lk [kvp1 "a.example." A [rd_a "203.0.113.7"]] ("example.", LZ_Static, [soa]) "a.example." TXT == Just (NoErr,   [], [soa])
-- True
-- >>> lk [kvp1 "a.example." A [rd_a "203.0.113.7"]] ("example.", LZ_Static, [soa]) "x.example." A   == Just (NameErr, [], [soa])
-- True
-- >>> lk [kvp1 "example." A [rd_a "203.0.113.7"]] ("example.", LZ_Redirect, [soa]) "a.example." A   == Just (NoErr, [rrset "a.example." A [rd_a "203.0.113.7"]], [])
-- True
lookupName :: Map Domain [RRset] -> (Domain, LocalZoneType, [RRset]) -> Question -> Maybe ResultRRS
lookupName nMap (apex, zt, soa) q = result zt
  where
    result LZ_Deny      =        lookup' Nothing             deny
    result LZ_Refuse    = Just $ lookup' (Refused, [], soa)  refuse
    result LZ_Static    = Just $ lookup' (NameErr, [], soa)  static
    result LZ_Redirect  = Just $ lookupName' nMap q{qname = apex} (NoErr, [], soa) redirect
    lookup' = lookupName' nMap q
    deny rrss
        | null rrss  = Nothing
        | otherwise  = Just (NoErr, rrss, [])
    refuse rrss
        | null rrss  = (Refused, [], soa)
        | otherwise  = (NoErr, rrss, [])
    static rrss
        | null rrss  = (NoErr, [], soa)
        | otherwise  = (NoErr, rrss, [])
    redirect rrss
        | null rrss  = (NoErr, [], soa)
        | otherwise  = (NoErr, [ rrs {rrsName = qname q} | rrs <- rrss ], [])
{- FOURMOLU_ENABLE -}
