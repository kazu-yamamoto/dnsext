{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module DNS.Iterative.Stats where

import Control.Concurrent
import Control.Monad
import DNS.Array
import DNS.SEC
import DNS.SVCB
import DNS.Types
import DNS.Types.Internal hiding (Builder)
import Data.Array
import Data.Array.IO
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

newtype StatsIx = StatsIx Int deriving (Eq, Ord, Enum, Ix)

{- FOURMOLU_DISABLE -}
pattern StatsIxMin      :: StatsIx
pattern StatsIxMin       = StatsIx 0

pattern CacheHit        :: StatsIx
pattern CacheHit         = StatsIx 0
pattern CacheMiss       :: StatsIx
pattern CacheMiss        = StatsIx 1

pattern ResolveDenied   :: StatsIx
pattern ResolveDenied    = StatsIx 2

pattern QueryTypeRes    :: StatsIx
pattern QueryTypeRes     = StatsIx 3
pattern QueryTypeA      :: StatsIx
pattern QueryTypeA       = StatsIx 4
pattern QueryTypeA6     :: StatsIx
pattern QueryTypeA6      = StatsIx 5
pattern QueryTypeAAAA   :: StatsIx
pattern QueryTypeAAAA    = StatsIx 6
pattern QueryTypeANY    :: StatsIx
pattern QueryTypeANY     = StatsIx 7
pattern QueryTypeCNAME  :: StatsIx
pattern QueryTypeCNAME   = StatsIx 8
pattern QueryTypeDNSKEY :: StatsIx
pattern QueryTypeDNSKEY  = StatsIx 9
pattern QueryTypeDS     :: StatsIx
pattern QueryTypeDS      = StatsIx 10
pattern QueryTypeHINFO  :: StatsIx
pattern QueryTypeHINFO   = StatsIx 11
pattern QueryTypeHTTPS  :: StatsIx
pattern QueryTypeHTTPS   = StatsIx 12
pattern QueryTypeMX     :: StatsIx
pattern QueryTypeMX      = StatsIx 13
pattern QueryTypeNAPTR  :: StatsIx
pattern QueryTypeNAPTR   = StatsIx 14
pattern QueryTypeNS     :: StatsIx
pattern QueryTypeNS      = StatsIx 15
pattern QueryTypeNULL   :: StatsIx
pattern QueryTypeNULL    = StatsIx 16
pattern QueryTypePTR    :: StatsIx
pattern QueryTypePTR     = StatsIx 17
pattern QueryTypeRRSIG  :: StatsIx
pattern QueryTypeRRSIG   = StatsIx 18
pattern QueryTypeSOA    :: StatsIx
pattern QueryTypeSOA     = StatsIx 19
pattern QueryTypeSPF    :: StatsIx
pattern QueryTypeSPF     = StatsIx 20
pattern QueryTypeSRV    :: StatsIx
pattern QueryTypeSRV     = StatsIx 21
pattern QueryTypeSSHFP  :: StatsIx
pattern QueryTypeSSHFP   = StatsIx 22
pattern QueryTypeSVCB   :: StatsIx
pattern QueryTypeSVCB    = StatsIx 23
pattern QueryTypeTLSA   :: StatsIx
pattern QueryTypeTLSA    = StatsIx 24
pattern QueryTypeTXT    :: StatsIx
pattern QueryTypeTXT     = StatsIx 25
pattern QueryTypeWKS    :: StatsIx
pattern QueryTypeWKS     = StatsIx 26
pattern QueryTypeOther  :: StatsIx
pattern QueryTypeOther   = StatsIx 27

pattern DNSClassRes     :: StatsIx
pattern DNSClassRes      = StatsIx 28
pattern DNSClassANY     :: StatsIx
pattern DNSClassANY      = StatsIx 29
pattern DNSClassCH      :: StatsIx
pattern DNSClassCH       = StatsIx 30
pattern DNSClassIN      :: StatsIx
pattern DNSClassIN       = StatsIx 31
pattern DNSClassOther   :: StatsIx
pattern DNSClassOther    = StatsIx 32

pattern FlagAA          :: StatsIx
pattern FlagAA           = StatsIx 33
pattern FlagAD          :: StatsIx
pattern FlagAD           = StatsIx 34
pattern FlagCD          :: StatsIx
pattern FlagCD           = StatsIx 35
pattern FlagQR          :: StatsIx
pattern FlagQR           = StatsIx 36
pattern FlagRA          :: StatsIx
pattern FlagRA           = StatsIx 37
pattern FlagRD          :: StatsIx
pattern FlagRD           = StatsIx 38
pattern FlagTC          :: StatsIx
pattern FlagTC           = StatsIx 39

pattern RcodeFormErr    :: StatsIx
pattern RcodeFormErr     = StatsIx 40
pattern RcodeNoError    :: StatsIx
pattern RcodeNoError     = StatsIx 41
pattern RcodeNXDomain   :: StatsIx
pattern RcodeNXDomain    = StatsIx 42
pattern RcodeNotImpl    :: StatsIx
pattern RcodeNotImpl     = StatsIx 43
pattern RcodeRefused    :: StatsIx
pattern RcodeRefused     = StatsIx 44
pattern RcodeServFail   :: StatsIx
pattern RcodeServFail    = StatsIx 45
pattern RcodeNoData     :: StatsIx
pattern RcodeNoData      = StatsIx 46

pattern StatsIxMax      :: StatsIx
pattern StatsIxMax       = StatsIx 46
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
labels :: Array StatsIx Builder
labels = array (StatsIxMin, StatsIxMax) [
    (CacheHit,         "cache_hit")
  , (CacheMiss,        "cache_miss")
  , (ResolveDenied,    "resolve_denied")
  , (QueryTypeRes,     "query_types_total{type=\"Reserved\"}")
  , (QueryTypeA,       "query_types_total{type=\"A\"}")
  , (QueryTypeA6,      "query_types_total{type=\"A6\"}")
  , (QueryTypeAAAA,    "query_types_total{type=\"AAAA\"}")
  , (QueryTypeANY,     "query_types_total{type=\"ANY\"}")
  , (QueryTypeCNAME,   "query_types_total{type=\"CANME\"}")
  , (QueryTypeDNSKEY,  "query_types_total{type=\"DNSKEY\"}")
  , (QueryTypeDS,      "query_types_total{type=\"DS\"}")
  , (QueryTypeHINFO,   "query_types_total{type=\"HINFO\"}")
  , (QueryTypeHTTPS,   "query_types_total{type=\"HTTPS\"}")
  , (QueryTypeMX,      "query_types_total{type=\"MX\"}")
  , (QueryTypeNAPTR,   "query_types_total{type=\"NAPTR\"}")
  , (QueryTypeNS,      "query_types_total{type=\"NS\"}")
  , (QueryTypeNULL,    "query_types_total{type=\"NULL\"}")
  , (QueryTypePTR,     "query_types_total{type=\"PTR\"}")
  , (QueryTypeRRSIG,   "query_types_total{type=\"RRSIG\"}")
  , (QueryTypeSOA,     "query_types_total{type=\"SOA\"}")
  , (QueryTypeSPF,     "query_types_total{type=\"SPF\"}")
  , (QueryTypeSRV,     "query_types_total{type=\"SRV\"}")
  , (QueryTypeSSHFP,   "query_types_total{type=\"SSHFP\"}")
  , (QueryTypeSVCB,    "query_types_total{type=\"SVCB\"}")
  , (QueryTypeTLSA,    "query_types_total{type=\"TLSA\"}")
  , (QueryTypeTXT,     "query_types_total{type=\"TXT\"}")
  , (QueryTypeWKS,     "query_types_total{type=\"WKS\"}")
  , (QueryTypeOther,   "query_types_total{type=\"other\"}")
  , (DNSClassRes,      "query_classes_total{type=\"Reserved\"}")
  , (DNSClassANY,      "query_classes_total{type=\"ANY\"}")
  , (DNSClassCH,       "query_classes_total{type=\"CH\"}")
  , (DNSClassIN,       "query_classes_total{type=\"IN\"}")
  , (DNSClassOther,    "query_classes_total{type=\"Other\"}")
  , (FlagAA,           "query_flags_total{type=\"AA\"}")
  , (FlagAD,           "query_flags_total{type=\"AD\"}")
  , (FlagCD,           "query_flags_total{type=\"CD\"}")
  , (FlagQR,           "query_flags_total{type=\"QR\"}")
  , (FlagRA,           "query_flags_total{type=\"RA\"}")
  , (FlagRD,           "query_flags_total{type=\"RD\"}")
  , (FlagTC,           "query_flags_total{type=\"TC\"}")
  , (RcodeFormErr,     "answer_rcodes_total{type=\"FORMERR\"}")
  , (RcodeNoError,     "answer_rcodes_total{type=\"NOERROR\"}")
  , (RcodeNotImpl,     "answer_rcodes_total{type=\"NOTIMPL\"}")
  , (RcodeNXDomain,    "answer_rcodes_total{type=\"NXDOMAIN\"}")
  , (RcodeRefused,     "answer_rcodes_total{type=\"REFUSED\"}")
  , (RcodeServFail,    "answer_rcodes_total{type=\"SERVFAIL\"}")
  , (RcodeNoData,      "answer_rcodes_total{type=\"nodata\"}")
  ]
{- FOURMOLU_ENABLE -}

newtype Stats = Stats (Array Int (IOUArray StatsIx Int))

{- FOURMOLU_DISABLE -}
fromQueryTypes :: Map TYPE StatsIx
fromQueryTypes = Map.fromList [
    (TYPE 0,   QueryTypeRes)
  , (A,        QueryTypeA)
  , (TYPE 38,  QueryTypeA6)
  , (AAAA,     QueryTypeAAAA)
  , (TYPE 255, QueryTypeANY)
  , (CNAME,    QueryTypeCNAME)
  , (DNSKEY,   QueryTypeDNSKEY)
  , (DS,       QueryTypeDS)
  , (TYPE 13,  QueryTypeHINFO)
  , (HTTPS,    QueryTypeHTTPS)
  , (MX,       QueryTypeMX)
  , (TYPE 35,  QueryTypeNAPTR)
  , (NS,       QueryTypeNS)
  , (NULL,     QueryTypeNULL)
  , (PTR,      QueryTypePTR)
  , (RRSIG,    QueryTypeRRSIG)
  , (SOA,      QueryTypeSOA)
  , (TYPE 99,  QueryTypeSPF)
  , (SRV,      QueryTypeSRV)
  , (TYPE 44,  QueryTypeSSHFP)
  , (SVCB,     QueryTypeSVCB)
  , (TLSA,     QueryTypeTLSA)
  , (TXT,      QueryTypeTXT)
  , (TYPE 11,  QueryTypeWKS)
  ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fromDNSClass :: Map CLASS StatsIx
fromDNSClass = Map.fromList [
    (CLASS 0,   DNSClassRes)
  , (CLASS 255, DNSClassANY)
  , (CLASS 3,   DNSClassCH)
  , (IN,        DNSClassIN)
  ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fromRcode :: Map RCODE StatsIx
fromRcode = Map.fromList [
    (FormatErr, RcodeFormErr)
  , (NotImpl,   RcodeNotImpl)
  , (NameErr,   RcodeNXDomain)
  , (Refused,   RcodeRefused)
  , (ServFail,  RcodeServFail)
  ]
{- FOURMOLU_ENABLE -}

newStats :: IO Stats
newStats = do
    n <- getNumCapabilities
    Stats . listArray (0, n - 1) <$> new n
  where
    new n = sequence $ replicate n $ newArray (StatsIxMin, StatsIxMax) 0

incStats :: Stats -> StatsIx -> IO ()
incStats (Stats stats) ix = do
    (i, _) <- myThreadId >>= threadCapability
    void $ atomicModifyIntArray (stats ! i) ix (+ 1)

incStatsM :: Ord a => Stats -> Map a StatsIx -> a -> Maybe StatsIx -> IO ()
incStatsM s m k mk = do
    case Map.lookup k m of
        Nothing -> case mk of
            Nothing -> return ()
            Just dx -> incStats s dx
        Just ix -> incStats s ix

readStats :: Stats -> Builder -> IO Builder
readStats (Stats stats) prefix = do
    n <- getNumCapabilities
    go n StatsIxMin mempty
  where
    toB :: Int -> Builder
    toB = lazyByteString . BL.pack . show
    go :: Int -> StatsIx -> Builder -> IO Builder
    go n ix b
        | ix > StatsIxMax = return b
        | otherwise = do
            v <- sumup 0 n ix 0
            let b' = b <> prefix <> (labels ! ix) <> " " <> toB v <> "\n"
            go n (succ ix) b'
    sumup :: Int -> Int -> StatsIx -> Int -> IO Int
    sumup i n ix acc
        | i < n = do
            v <- readArray (stats ! i) ix
            sumup (i + 1) n ix (acc + v)
        | otherwise = return acc
