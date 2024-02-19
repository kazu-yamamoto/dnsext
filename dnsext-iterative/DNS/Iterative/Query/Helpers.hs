module DNS.Iterative.Query.Helpers where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.RRCache (Ranking)
import DNS.SEC
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Types

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> import DNS.Types

rrListWith
    :: TYPE
    -> (DNS.RData -> Maybe rd)
    -> Domain
    -> (rd -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
rrListWith typ fromRD dom = rrListWith' typ fromRD (== dom)

rrListWith'
    :: TYPE
    -> (DNS.RData -> Maybe rd)
    -> (Domain -> Bool)
    -> (rd -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
rrListWith' typ fromRD dpred h = foldr takeRR []
  where
    takeRR rr@ResourceRecord{rdata = rd} xs
        | dpred (rrname rr), rrtype rr == typ, Just ds <- fromRD rd = h ds rr : xs
    takeRR _ xs = xs

rrsigList :: Domain -> TYPE -> [ResourceRecord] -> [(RD_RRSIG, TTL)]
rrsigList dom typ rrs = rrListWith RRSIG (sigrdWith typ <=< DNS.fromRData) dom pair rrs
  where
    pair rd rr = (rd, rrttl rr)

rrsetGoodSigs :: RRset -> [RD_RRSIG]
rrsetGoodSigs = mayVerifiedRRS [] (const []) id . rrsMayVerified

rrsetValid :: RRset -> Bool
rrsetValid = mayVerifiedRRS False (const False) (const True) . rrsMayVerified

sigrdWith :: TYPE -> RD_RRSIG -> Maybe RD_RRSIG
sigrdWith sigType sigrd = guard (rrsig_type sigrd == sigType) *> return sigrd

withSection
    :: (m -> ([ResourceRecord], Ranking))
    -> m
    -> ([ResourceRecord] -> Ranking -> a)
    -> a
withSection getRanked msg body = uncurry body $ getRanked msg

nsList
    :: Domain
    -> (Domain -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
nsList = rrListWith NS $ \rd -> DNS.rdataField rd DNS.ns_domain

cnameList
    :: Domain
    -> (Domain -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
cnameList = rrListWith CNAME $ \rd -> DNS.rdataField rd DNS.cname_domain

axList
    :: Bool
    -> (Domain -> Bool)
    -> (IP -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
axList disableV6NS pdom h = foldr takeAx []
  where
    takeAx rr@ResourceRecord{rrtype = A, rdata = rd} xs
        | pdom (rrname rr)
        , Just v4 <- DNS.rdataField rd DNS.a_ipv4 =
            h (IPv4 v4) rr : xs
    takeAx rr@ResourceRecord{rrtype = AAAA, rdata = rd} xs
        | not disableV6NS && pdom (rrname rr)
        , Just v6 <- DNS.rdataField rd DNS.aaaa_ipv6 =
            h (IPv6 v6) rr : xs
    takeAx _ xs = xs

-- | The existence or non-existence of a Delegation is independent of the existence of [DS_RD].
-- >>> mkRR n ty rd = ResourceRecord n ty IN 3600000 rd
-- >>> ns = [mkRR "." NS $ rd_ns "m.root-servers.net."]
-- >>> as =[mkRR "m.root-servers.net." A $ rd_a "202.12.27.33", mkRR "m.root-servers.net." AAAA $ rd_aaaa "2001:dc3::35"]
-- >>> delegationNS . ($ []) <$> findDelegation (nsList (fromString ".") (,) ns) as
-- Just (DEwithAx "m.root-servers.net." 202.12.27.33 :| [DEwithAx "m.root-servers.net." 2001:dc3::35])
findDelegation :: [(Domain, ResourceRecord)] -> [ResourceRecord] -> Maybe ([RD_DS] -> Delegation)
findDelegation = findDelegation' (\dom ents dss -> Delegation dom ents (FilledDS dss) [] FreshD)

findDelegation' :: (Domain -> NonEmpty DEntry -> a) -> [(Domain, ResourceRecord)] -> [ResourceRecord] -> Maybe a
findDelegation' k nsps adds = do
    ((_, rr), _) <- uncons nsps
    let nss = map fst nsps
    ents <- nonEmpty $ concatMap (uncurry dentries) $ rrnamePairs (sort nss) addgroups
    {- only data from delegation source zone. get DNSKEY from destination zone -}
    Just $ k (rrname rr) ents
  where
    addgroups = groupBy ((==) `on` rrname) $ sortOn ((,) <$> rrname <*> rrtype) adds
    dentries d [] = [DEonlyNS d]
    dentries d as@(_ : _)
        | null axs = [DEonlyNS d]
        | otherwise = axs
      where
        {- -----  -----  - domains are filtered by rrnamePairs, here does not check them -}
        axs = axList False (const True) (\ip _ -> DEwithAx d ip) as

-- | pairing correspond rrname domain data
--
-- >>> let agroup n = [ ResourceRecord { rrname = n, rrtype = A, rrclass = IN, rrttl = 60, rdata = DNS.rd_a a } | a <- ["10.0.0.1", "10.0.0.2"] ]
-- >>> rrnamePairs ["s", "t", "u"] [agroup "s", agroup "t", agroup "u"] == [("s", agroup "s"), ("t", agroup "t"), ("u", agroup "u")]
-- True
-- >>> rrnamePairs ["t"] [agroup "s", agroup "t", agroup "u"] == [("t", agroup "t")]
-- True
-- >>> rrnamePairs ["s", "t", "u"] [agroup "t"] == [("s", []), ("t", agroup "t"), ("u", [])]
-- True
rrnamePairs :: [Domain] -> [[ResourceRecord]] -> [(Domain, [ResourceRecord])]
rrnamePairs [] _gs = []
rrnamePairs (d : ds) [] = (d, []) : rrnamePairs ds []
rrnamePairs dds@(d : ds) ggs@(g : gs)
    | d < an = (d, []) : rrnamePairs ds ggs
    | d == an = (d, g) : rrnamePairs ds gs
    | otherwise {- d >  an  -} = rrnamePairs dds gs -- unknown additional RRs. just skip
  where
    an = rrname a
    a = head g

{- FOURMOLU_DISABLE -}
list1 :: b -> ([a] -> b) ->  [a] -> b
list1 nil _        []   =  nil
list1 _   cons xs@(_:_) =  cons xs

list :: b -> (a -> [a] -> b) ->  [a] -> b
list nil _     []    =  nil
list _   cons (x:xs) =  cons x xs
{- FOURMOLU_ENABLE -}
