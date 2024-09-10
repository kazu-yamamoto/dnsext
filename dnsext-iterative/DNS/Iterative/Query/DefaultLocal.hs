
module DNS.Iterative.Query.DefaultLocal (
    defaultLocal,
) where

-- GHC packages
import Data.String

-- dnsext-* packages
import DNS.Types

-- this package
import DNS.Iterative.Query.Types

defaultLocal :: [(Domain, LocalZoneType, [ResourceRecord])]
defaultLocal =
    [ localhost
    , home_arpa
    , test
    , onion
    , invalid
    ]

---

{- FOURMOLU_DISABLE -}
-- localhost (RFC 6761) - https://datatracker.ietf.org/doc/html/rfc6761#section-6.3
-- local-zone: "localhost." redirect
-- local-data: "localhost. 10800 IN NS localhost."
-- local-data: "localhost. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800"
-- local-data: "localhost. 10800 IN A 127.0.0.1"
-- local-data: "localhost. 10800 IN AAAA ::1"
localhost :: (Domain, LocalZoneType, [ResourceRecord])
localhost =
    defineZone "localhost." LZ_Static
    [ mkRR "localhost." 10800 IN NS        localNS
    , mkRR "localhost." 10800 IN SOA       localSOA
    , mkRR "localhost." 10800 IN A       $ rd_a    $ read_ "DefaultLocal: fail to parse IPv4 address" "127.0.0.1"
    , mkRR "localhost." 10800 IN AAAA    $ rd_aaaa $ read_ "DefaultLocal: fail to parse IPv6 address" "::1"
    ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- home.arpa (RFC 8375) - https://datatracker.ietf.org/doc/html/rfc8375#section-4
{- TODO:
 That is, queries for
 'home.arpa.' and subdomains of 'home.arpa.'  MUST NOT be
 forwarded, with one important exception: a query for a DS
 record with the DO bit set MUST return the correct answer for
 that question, including correct information in the authority
 section that proves that the record is nonexistent.           -}
-- local-zone: "home.arpa." static
-- local-data: "home.arpa. 10800 IN NS localhost."
-- local-data: "home.arpa. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800"
home_arpa :: (Domain, LocalZoneType, [ResourceRecord])
home_arpa =
    defineZone "home.arpa." LZ_Static
    [ mkRR "home.arpa." 10800 IN NS        localNS
    , mkRR "home.arpa." 10800 IN SOA       localSOA
    ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- onion (RFC 7686) - https://datatracker.ietf.org/doc/html/rfc7686#section-2
-- local-zone: "onion." static
-- local-data: "onion. 10800 IN NS localhost."
-- local-data: "onion. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800"
onion :: (Domain, LocalZoneType, [ResourceRecord])
onion =
    defineZone "onion." LZ_Static
    [ mkRR "onion." 10800 IN NS            localNS
    , mkRR "onion." 10800 IN SOA           localSOA
    ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- test. (RFC 6761) - https://datatracker.ietf.org/doc/html/rfc6761#section-6.2
-- local-zone: "test." static
-- local-data: "test. 10800 IN NS localhost."
-- local-data: "test. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800"
test :: (Domain, LocalZoneType, [ResourceRecord])
test =
    defineZone "test." LZ_Static
    [ mkRR "test." 10800 IN NS             localNS
    , mkRR "test." 10800 IN SOA            localSOA
    ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- invalid (RFC 6761) - https://datatracker.ietf.org/doc/html/rfc6761#section-6.4
-- local-zone: "invalid." static
-- local-data: "invalid. 10800 IN NS localhost."
-- local-data: "invalid. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800"
invalid :: (Domain, LocalZoneType, [ResourceRecord])
invalid =
    defineZone "invalid." LZ_Static
    [ mkRR "invalid." 10800 IN NS          localNS
    , mkRR "invalid." 10800 IN SOA         localSOA
    ]
{- FOURMOLU_ENABLE -}

---

defineZone :: String -> LocalZoneType -> [ResourceRecord] -> (Domain, LocalZoneType, [ResourceRecord])
defineZone name ztype rrs = (domain name, ztype, rrs)

mkRR :: String -> TTL -> CLASS -> TYPE -> RData -> ResourceRecord
mkRR name ttl cls typ rd = ResourceRecord { rrname = domain name, rrttl = ttl, rrclass = cls, rrtype = typ, rdata = rd }

localNS :: RData
localNS = rd_ns (domain "localhost.")

localSOA :: RData
localSOA = rd_soa (domain "localhost.") (fromString "nobody@invalid.") 1 3600 1200 604800 10800

domain :: String -> Domain
domain = fromString

read_ :: Read a => String -> String -> a
read_ msg s = case [x | (x, "") <- reads s] of
    []   -> error $ msg ++ ": " ++ s
    x:_  -> x

{- FOURMOLU_DISABLE -}
_pprZone :: (Domain, LocalZoneType, [ResourceRecord]) -> String
_pprZone (apex, ztype, rrs) =
    unlines $
    [ show apex
    , show ztype
    ] ++
    map (("  " ++) . show) rrs
{- FOURMOLU_ENABLE -}
