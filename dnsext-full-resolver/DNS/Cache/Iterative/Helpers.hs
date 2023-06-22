module DNS.Cache.Iterative.Helpers where

-- GHC packages
import Control.Monad (guard, (<=<))
import Data.Function (on)
import Data.List (groupBy, sort, sortOn, uncons)

-- other packages

-- dns packages

import DNS.Do53.Memo (
    Ranking,
 )
import DNS.SEC (
    RD_DS,
    RD_RRSIG (..),
    TYPE (RRSIG),
 )
import DNS.Types (
    Domain,
    ResourceRecord (..),
    TTL,
    TYPE (A, AAAA, CNAME, NS),
 )
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))

-- this package
import DNS.Cache.Iterative.Types

-- $setup
-- >>> import DNS.Types

rrListWith
    :: TYPE
    -> (DNS.RData -> Maybe rd)
    -> Domain
    -> (rd -> ResourceRecord -> a)
    -> [ResourceRecord]
    -> [a]
rrListWith typ fromRD dom h = foldr takeRR []
  where
    takeRR rr@ResourceRecord{rdata = rd} xs
        | rrname rr == dom, rrtype rr == typ, Just ds <- fromRD rd = h ds rr : xs
    takeRR _ xs = xs

rrsigList :: Domain -> TYPE -> [ResourceRecord] -> [(RD_RRSIG, TTL)]
rrsigList dom typ rrs = rrListWith RRSIG (sigrdWith typ <=< DNS.fromRData) dom pair rrs
  where
    pair rd rr = (rd, rrttl rr)

rrsetGoodSigs :: RRset -> [RD_RRSIG]
rrsetGoodSigs = mayVerifiedRRS [] [] id . rrsMayVerified

rrsetValid :: RRset -> Bool
rrsetValid = mayVerifiedRRS False False (const True) . rrsMayVerified

{-# DEPRECATED rrsetVerified "use rrsetValid instead of this" #-}
rrsetVerified :: RRset -> Bool
rrsetVerified = rrsetValid

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

takeDelegationSrc
    :: [(Domain, ResourceRecord)]
    -> [RD_DS]
    -> [ResourceRecord]
    -> Maybe Delegation
takeDelegationSrc nsps dss adds = do
    (p@(_, rr), ps) <- uncons nsps
    let nss = map fst (p : ps)
    ents <- uncons $ concatMap (uncurry dentries) $ rrnamePairs (sort nss) addgroups
    {- only data from delegation source zone. get DNSKEY from destination zone -}
    return $ Delegation (rrname rr) ents (FilledDS dss) []
  where
    addgroups = groupBy ((==) `on` rrname) $ sortOn ((,) <$> rrname <*> rrtype) adds
    dentries d [] = [DEonlyNS d]
    dentries d as@(_ : _)
        | null axs = [DEonlyNS d]
        | otherwise = axs
      where
        axs =
            axList
                False
                (const True {- paired by rrnamePairs -})
                (\ip _ -> DEwithAx d ip)
                as

-- | pairing correspond rrname domain data
--
-- >>> let agroup n = [ ResourceRecord { rrname = n, rrtype = A, rrclass = classIN, rrttl = 60, rdata = DNS.rd_a a } | a <- ["10.0.0.1", "10.0.0.2"] ]
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
