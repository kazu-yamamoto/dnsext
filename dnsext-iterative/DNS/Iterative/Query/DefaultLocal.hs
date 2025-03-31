{-# LANGUAGE FlexibleContexts #-}

module DNS.Iterative.Query.DefaultLocal (
    defaultLocal,
    hideIdentity,
    hideVersion,
    identity,
    version,
) where

-- GHC packages
import Data.String

-- dnsext-* packages
import DNS.Types
import Data.IP (AddrRange, IPv6, fromIPv4)
import qualified Data.IP as IP

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Class

{- FOURMOLU_DISABLE -}
defaultLocal :: [(Domain, LocalZoneType, [RR])]
defaultLocal =
    [ localhost
    , home_arpa
    , test
    , onion
    , invalid
    ] ++
    ipv4RevZones ++
    ipv6RevZones
{- FOURMOLU_ENABLE -}

---

identity :: String -> [(Domain, LocalZoneType, [RR])]
identity istr = [defineZone n LZ_Static [mkRR n 0 CH TXT (rd_txt $ fromString istr)] | n <- ["id.server.", "hostname.bind."]]

version :: String -> [(Domain, LocalZoneType, [RR])]
version vstr = [defineZone n LZ_Static [mkRR n 0 CH TXT (rd_txt $ fromString vstr)] | n <- ["version.server.", "version.bind."]]

hideIdentity :: [(Domain, LocalZoneType, [RR])]
hideIdentity = [defineZone n LZ_Refuse [] | n <- ["id.server.", "hostname.bind."]]

hideVersion :: [(Domain, LocalZoneType, [RR])]
hideVersion = [defineZone n LZ_Static [] | n <- ["version.server.", "version.bind."]]

---

{- FOURMOLU_DISABLE -}
-- localhost (RFC 6761) - https://datatracker.ietf.org/doc/html/rfc6761#section-6.3
-- local-zone: "localhost." redirect
-- local-data: "localhost. 10800 IN NS localhost."
-- local-data: "localhost. 10800 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 10800"
-- local-data: "localhost. 10800 IN A 127.0.0.1"
-- local-data: "localhost. 10800 IN AAAA ::1"
localhost :: (Domain, LocalZoneType, [RR])
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
home_arpa :: (Domain, LocalZoneType, [RR])
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
onion :: (Domain, LocalZoneType, [RR])
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
test :: (Domain, LocalZoneType, [RR])
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
invalid :: (Domain, LocalZoneType, [RR])
invalid =
    defineZone "invalid." LZ_Static
    [ mkRR "invalid." 10800 IN NS          localNS
    , mkRR "invalid." 10800 IN SOA         localSOA
    ]
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
ipv4RevZones :: [(Domain, LocalZoneType, [RR])]
ipv4RevZones = [defineV4RevZone prefix | cidr <- cidrs, prefix <- prefixFromIPv4CIDR cidr]
  where
    cidrs =
        -- https://datatracker.ietf.org/doc/html/rfc6303#section-4.1 - RFC 1918 Zones
        "10.0.0.0/8"          :
        "172.16.0.0/12"       :
        "192.168.0.0/16"      :
        -- https://datatracker.ietf.org/doc/html/rfc6303#section-4.2 - RFC 5735 and RFC 5737 Zones
        "0.0.0.0/8"           :
        "127.0.0.0/8"         :
        "169.254.0.0/16"      :
        "192.0.2.0/24"        :
        "198.51.100.0/24"     :
        "203.0.113.0/24"      :
        "255.255.255.255/32"  :
        -- https://datatracker.ietf.org/doc/html/rfc6598#section-4 - Use of Shared CGN Space
        "100.64.0.0/10"       :
        --
        []
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
ipv6RevZones :: [(Domain, LocalZoneType, [RR])]
ipv6RevZones = [defineV6RevZone prefix | cidr <- cidrs, prefix <- prefixFromIPv6CIDR cidr]
  where
    cidrs =
        -- https://datatracker.ietf.org/doc/html/rfc6303#section-4.3 - Local IPv6 Unicast Addresses
        "::1/128"             :
        "::/128"              :
        -- https://datatracker.ietf.org/doc/html/rfc6303#section-4.4 - IPv6 Locally Assigned Local Addresses
        "fd00::/8"            :
        -- https://datatracker.ietf.org/doc/html/rfc6303#section-4.5 - IPv6 Link-Local Addresses
        "fe80::/10"           :
        -- https://datatracker.ietf.org/doc/html/rfc6303#section-4.6 - IPv6 Example Prefix
        "2001:db8::/32"       :
        --
        []
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
defineV4RevZone :: [Int] -> (Domain, LocalZoneType, [RR])
defineV4RevZone prefix =
    defineZone name LZ_Static
    [ mkRR name       10800 IN SOA         localSOA
    ]
  where
    name = fromString $ foldr poctet "in-addr.arpa." $ reverse prefix
    poctet o tl  = show o ++ "." ++ tl
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
defineV6RevZone :: [Int] -> (Domain, LocalZoneType, [RR])
defineV6RevZone prefix =
    defineZone name LZ_Static
    [ mkRR name       10800 IN SOA         localSOA
    ]
  where
    name = fromString $ foldr phex "ip6.arpa." $ reverse prefix
    phex h tl  = showHex h ("." ++ tl)
{- FOURMOLU_ENABLE -}

prefixFromIPv4CIDR :: String -> [[Int]]
prefixFromIPv4CIDR cidr = prefixFromRange 8 fromIPv4 (read_ "fail to parse AddrRange from CIDR" cidr)

prefixFromIPv6CIDR :: String -> [[Int]]
prefixFromIPv6CIDR cidr = prefixFromRange 4 fromIPv6h (read_ "fail to parse AddrRange from CIDR" cidr)

{- FOURMOLU_DISABLE -}
prefixFromRange :: Int -> (a -> [Int]) -> AddrRange a -> [[Int]]
prefixFromRange pwidth partList range
    | wrem == 0  = [prefix]
    | otherwise  = [prefix ++ [next + lp] | lp <- [0 .. 2^(pwidth - wrem) - 1]]
  where
    (prefix, next) = case splitAt pc $ partList $ IP.addr range of
        (p, [])   -> (p, 0)
        (p, x:_)  -> (p, x)
    (pc, wrem) = IP.mlen range `quotRem` pwidth
{- FOURMOLU_ENABLE -}

---

defineZone :: String -> LocalZoneType -> [RR] -> (Domain, LocalZoneType, [RR])
defineZone name ztype rrs = (domain name, ztype, rrs)

mkRR :: String -> TTL -> CLASS -> TYPE -> RData -> RR
mkRR name ttl cls typ rd = ResourceRecord{rrname = domain name, rrttl = ttl, rrclass = cls, rrtype = typ, rdata = rd}

localNS :: RData
localNS = rd_ns (domain "localhost.")

localSOA :: RData
localSOA = rd_soa (domain "localhost.") (fromString "nobody@invalid.") 1 3600 1200 604800 10800

domain :: String -> Domain
domain = fromString

fromIPv6h :: IPv6 -> [Int]
fromIPv6h ip6 = [h | b <- IP.fromIPv6b ip6, h <- [b `unsafeShiftR` 4, b .&. 0xf]]

read_ :: Read a => String -> String -> a
read_ msg s = case [x | (x, "") <- reads s] of
    [] -> error $ msg ++ ": " ++ s
    x : _ -> x

{- FOURMOLU_DISABLE -}
_pprZone :: (Domain, LocalZoneType, [RR]) -> String
_pprZone (apex, ztype, rrs) =
    unlines $
    [ show apex
    , show ztype
    ] ++
    map (("  " ++) . show) rrs
{- FOURMOLU_ENABLE -}
