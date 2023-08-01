{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Rev (
    takeSpecialRevDomainResult,
) where

-- GHC packages
import Control.Applicative ((<|>))
import Control.Arrow (first)
import Control.Monad (guard)
import Data.Bits (shiftL, (.|.))
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Short as Short
import Data.Function (on)
import Data.List (groupBy, intercalate, sortOn)
import qualified Data.List as L
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Maybe (listToMaybe)
import Numeric (readDec, readHex, showHex)

-- other packages

-- dns packages
import DNS.Types (
    Domain,
    ResourceRecord (..),
    TYPE (SOA),
    classIN,
 )
import qualified DNS.Types as DNS
import Data.IP (IPv4, IPv6, toIPv4, toIPv6b)
import qualified Data.IP as IP

-- this package
import DNS.Cache.Iterative.Types

-- $setup
-- >>> :set -XOverloadedStrings

-- result output tags for special IP-blocks
data EmbedResult
    = EmbedLocal
    | EmbedInAddr
    | EmbedIp6
    deriving (Show)

runEmbedResult :: Domain -> EmbedResult -> Result
runEmbedResult dom emb = (DNS.NameErr, [], [soa emb])
  where
    soa EmbedLocal = soaRR "localhost." "root@localhost." 1 604800 86400 2419200 604800
    soa EmbedInAddr = soaRR dom "." 0 28800 7200 604800 86400
    soa EmbedIp6 = soaRR dom "." 0 28800 7200 604800 86400
    soaRR mname mail ser refresh retry expire ncttl =
        ResourceRecord
            { rrname = dom
            , rrtype = SOA
            , rrclass = classIN
            , rrttl = ncttl
            , rdata = DNS.rd_soa mname mail ser refresh retry expire ncttl
            }

-- result for special IP-address block from reverse lookup domain
takeSpecialRevDomainResult :: Domain -> Maybe Result
takeSpecialRevDomainResult dom =
    fmap (uncurry runEmbedResult) $
        fst <$> v4EmbeddedResult dom <|> fst <$> v6EmbeddedResult dom

-- detect embedded result for special IP-address block from reverse lookup domain
takeEmbeddedResult
    :: (Ord a, IP.Addr a)
    => (Domain -> Either String [Int])
    -> ([Int] -> Domain)
    -> ([Int] -> (a, Int))
    -> [(Int, a, Map a EmbedResult)]
    -> Int
    -> Domain
    -> Maybe ((Domain, EmbedResult), IP.AddrRange a)
takeEmbeddedResult parse show_ withMaskLen blocks partWidth dom = do
    parts <- either (const Nothing) Just $ parse dom
    let (ip, len) = withMaskLen parts
    listToMaybe
        [ ((show_ $ take maskedPartsLen parts, result), IP.makeAddrRange prefix mlen)
        | (mlen, mask, pairs) <- blocks
        , len >= mlen
        , let prefix = IP.masked ip mask
        , Just result <- [Map.lookup prefix pairs]
        , let maskedPartsLen = ceiling (fromIntegral mlen / fromIntegral partWidth :: Rational)
        ]

v4EmbeddedResult :: Domain -> Maybe ((Domain, EmbedResult), IP.AddrRange IPv4)
v4EmbeddedResult =
    takeEmbeddedResult
        parseV4RevDomain
        showV4RevDomain
        withMaskLenV4
        specialV4Blocks
        8

v6EmbeddedResult :: Domain -> Maybe ((Domain, EmbedResult), IP.AddrRange IPv6)
v6EmbeddedResult =
    takeEmbeddedResult
        parseV6RevDomain
        showV6RevDomain
        withMaskLenV6
        specialV6Blocks
        4

-- | parse IPv4 8bit-parts from reverse-lookup domain
--
-- >>> parseV4RevDomain "1.2.3.4.in-addr.arpa."
-- Right [4,3,2,1]
parseV4RevDomain :: Domain -> Either String [Int]
parseV4RevDomain dom = do
    rparts <- maybe (throw "suffix does not match") Right $ L.stripPrefix sufV4 (reverse $ DNS.toWireLabels dom)
    let plen = length rparts
    maybe (throw $ "invalid number of parts split by dot: " ++ show rparts) Right $ guard (1 <= plen && plen <= 4)
    mapM getByte rparts
  where
    throw = Left . ("v4Rev: " ++)
    getByte s = do
        byte <- case [x | (x, "") <- readDec $ B8.unpack (Short.fromShort s)] of
            [] -> throw $ "cannot parse decimal from part: " ++ show s
            [x] -> Right x
            _ : _ -> throw $ "ambiguous parse result of decimal part: " ++ show s
        maybe (throw $ "decimal part '" ++ show byte ++ "' is out of range") Right $ guard (0 <= byte && byte < 256)
        return byte
    sufV4 = ["arpa", "in-addr"]

-- | parse IPv6 4bit-parts from reverse-lookup domain
--
-- >>> parseV6RevDomain "a.9.8.7.6.5.e.f.f.f.4.3.2.1.0.0.0.0.0.0.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa"
-- Right [2,0,0,1,0,13,11,8,0,15,0,0,0,0,0,0,0,0,1,2,3,4,15,15,15,14,5,6,7,8,9,10]
parseV6RevDomain :: Domain -> Either String [Int]
parseV6RevDomain dom = do
    rparts <- maybe (throw "suffix does not match") Right $ L.stripPrefix sufV6 (reverse $ DNS.toWireLabels dom)
    let plen = length rparts
    maybe (throw $ "invalid number of parts split by dot: " ++ show rparts) Right $ guard (1 <= plen && plen <= 32)
    mapM getHexDigit rparts
  where
    throw = Left . ("v6Rev: " ++)
    getHexDigit s = do
        h <- case [x | (x, "") <- readHex $ B8.unpack (Short.fromShort s)] of
            [] -> throw $ "cannot parse hexadecimal from part: " ++ show s
            [x] -> Right x
            _ : _ -> throw $ "ambiguous parse result of hexadecimal part: " ++ show s
        maybe (throw $ "hexadecimal part '" ++ showHex h "" ++ "' is out of range") Right $ guard (0 <= h && h < 0x10)
        return h
    sufV6 = ["arpa", "ip6"]

-- show IPv4 reverse-lookup domain from 8bit-parts
showV4RevDomain :: [Int] -> Domain
showV4RevDomain parts =
    DNS.fromRepresentation $ intercalate "." (map show $ reverse parts) ++ ".in-addr.arpa."

-- parse IPv6 reverse-lookup domain from 4bit-parts
showV6RevDomain :: [Int] -> Domain
showV6RevDomain parts =
    DNS.fromRepresentation $ intercalate "." (map (`showHex` "") $ reverse parts) ++ ".ip6.arpa."

-- make IPv4-address and mask-length from prefix 8bit-parts
withMaskLenV4 :: [Int] -> (IPv4, Int)
withMaskLenV4 bs = (toIPv4 $ take 4 $ bs ++ pad, length bs * 8)
  where
    pad = replicate (4 - 1) 0

-- make IPv6-address and mask-length from prefix 4bit-parts
withMaskLenV6 :: [Int] -> (IPv6, Int)
withMaskLenV6 hs = (toIPv6h $ take 32 $ hs ++ pad, length hs * 4)
  where
    pad = replicate (32 - 1) 0
    toIPv6h = toIPv6b . bytes
    bytes [] = []
    bytes [h] = [h `shiftL` 4]
    bytes (h : l : xs) = ((h `shiftL` 4) .|. l) : bytes xs

-----

{- IPv4 Special-Purpose Address Registry Entries
   https://datatracker.ietf.org/doc/html/rfc6890.html#section-2.2.2 -}
specialV4Blocks :: [(Int, IPv4, Map IPv4 EmbedResult)]
specialV4Blocks =
    map groupMap . groupByFst IP.mlen . map (first read) $
        [ ("0.0.0.0/8", EmbedLocal {- This host on this network  -})
        , ("10.0.0.0/8", EmbedInAddr {- Private-Use                -})
        , ("100.64.0.0/10", EmbedInAddr {- Shared Address Space       -})
        , ("127.0.0.0/8", EmbedLocal {- Loopback                   -})
        , ("169.254.0.0/16", EmbedInAddr {- Link Local                 -})
        , ("172.16.0.0/12", EmbedInAddr {- Private-Use                -})
        -- ("192.0.0.0/24"       , _          ) {- IETF Protocol Assignments  -} {- not handled in resolvers -}
        -- ("192.0.0.0/29"       , _          ) {- DS-Lite                    -} {- not handled in resolvers -}
        , ("192.0.2.0/24", EmbedInAddr {- Documentation (TEST-NET-1) -})
        -- ("192.88.99.0/24"     , _          ) {- 6to4 Relay Anycast         -} {- not handled in resolvers -}
        , ("192.168.0.0/16", EmbedInAddr {- Private-Use                -})
        -- ("198.18.0.0/15"      , _          ) {- Benchmarking               -} {- not handled in resolvers -}
        , ("198.51.100.0/24", EmbedInAddr {- Documentation (TEST-NET-2) -})
        , ("203.0.113.0/24", EmbedInAddr {- Documentation (TEST-NET-3) -})
        -- ("240.0.0.0/4"        , _          ) {- Reserved                   -} {- not handled in resolvers -}
        , ("255.255.255.255/32", EmbedInAddr {- Limited Broadcast          -})
        ]
  where
    groupByFst f = groupBy ((==) `on` f . fst) . sortOn (f . fst)
    groupMap rs =
        ( IP.mlen r
        , IP.mask r
        , Map.fromList [(IP.addr range, res) | (range, res) <- rs]
        )
      where
        r = fst $ head rs

{- IPv6 Special-Purpose Address Registry Entries
   https://datatracker.ietf.org/doc/html/rfc6890.html#section-2.2.3 -}
specialV6Blocks :: [(Int, IPv6, Map IPv6 EmbedResult)]
specialV6Blocks =
    map groupMap . groupByFst IP.mlen . map (first read) $
        [ ("::1/128", EmbedIp6 {- Loopback Address           -})
        , ("::/128", EmbedIp6 {- Unspecified Address        -})
        -- ("64:ff9b::/96"       , _          ) {- IPv4-IPv6 Translat.        -} {- not handled in resolvers -}
        -- ("::ffff:0.0.0.0/96"  , _          ) {- IPv4-mapped Address        -} {- not handled in resolvers -}
        -- ("100::/64"           , _          ) {- Discard-Only Address Block -} {- not handled in resolvers -}
        -- ("2001::/23"          , _          ) {- IETF Protocol Assignments  -} {- not handled in resolvers -}
        -- ("2001::/32"          , _          ) {- TEREDO                     -} {- not handled in resolvers -}
        -- ("2001:2::/48"        , _          ) {- Benchmarking               -} {- not handled in resolvers -}
        , ("2001:db8::/32", EmbedIp6 {- Documentation              -})
        -- ("2001:10::/28"       , _          ) {- ORCHID                     -} {- not handled in resolvers -}
        -- ("2002::/16"          , _          ) {- 6to4                       -} {- not handled in resolvers -}
        -- ("fc00::/7"           , _          ) {- Unique-Local               -} {- not handled in resolvers -}
        , ("fe80::/10", EmbedIp6 {- Linked-Scoped Unicast      -})
        ]
  where
    groupByFst f = groupBy ((==) `on` f . fst) . sortOn (f . fst)
    groupMap rs =
        ( IP.mlen r
        , IP.mask r
        , Map.fromList [(IP.addr range, res) | (range, res) <- rs]
        )
      where
        r = fst $ head rs
