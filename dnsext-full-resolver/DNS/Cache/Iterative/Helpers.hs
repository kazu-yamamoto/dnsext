module DNS.Cache.Iterative.Helpers where

-- GHC packages
import Control.Monad (guard, (<=<))
import Control.Monad.Trans.Except (throwE)

-- other packages

-- dns packages

import DNS.Do53.Memo (
    Ranking,
 )
import DNS.SEC (
    RD_RRSIG (..),
    TYPE (RRSIG),
 )
import DNS.Types (
    DNSError,
    Domain,
    ResourceRecord (..),
    TTL,
    TYPE (A, AAAA, CNAME, NS),
 )
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))

-- this package
import DNS.Cache.Iterative.Types

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

rrsetVerified :: RRset -> Bool
rrsetVerified = not . null . rrsGoodSigs

sigrdWith :: TYPE -> RD_RRSIG -> Maybe RD_RRSIG
sigrdWith sigType sigrd = guard (rrsig_type sigrd == sigType) *> return sigrd

withSection
    :: (m -> ([ResourceRecord], Ranking))
    -> m
    -> ([ResourceRecord] -> Ranking -> a)
    -> a
withSection getRanked msg body = uncurry body $ getRanked msg

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwE . DnsError

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
