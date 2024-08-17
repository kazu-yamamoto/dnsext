{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module DNS.Iterative.Stats where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import DNS.Array
import DNS.SEC
import DNS.SVCB
import DNS.Types
import DNS.Types.Internal hiding (Builder)
import Data.Array.IArray
import Data.Array.IO
import Data.Array.Unboxed
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Functor
import Data.Int
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

import Network.Socket (SockAddr (..))

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

pattern QueriesAll      :: StatsIx
pattern QueriesAll       = StatsIx 47

pattern QueryIPv4       :: StatsIx
pattern QueryIPv4        = StatsIx 48

pattern QueryIPv6       :: StatsIx
pattern QueryIPv6        = StatsIx 49

pattern QueryDO         :: StatsIx
pattern QueryDO          = StatsIx 50

pattern QueryTCP        :: StatsIx
pattern QueryTCP         = StatsIx 51
pattern QueryTLS        :: StatsIx
pattern QueryTLS         = StatsIx 52
pattern QueryHTTPS      :: StatsIx
pattern QueryHTTPS       = StatsIx 53
pattern QueryQUIC       :: StatsIx
pattern QueryQUIC        = StatsIx 54
pattern QueryHTTP3      :: StatsIx
pattern QueryHTTP3       = StatsIx 55

pattern QueryUDP53      :: StatsIx
pattern QueryUDP53       = StatsIx 56
pattern QueryTCP53      :: StatsIx
pattern QueryTCP53       = StatsIx 57
pattern QueryDoT        :: StatsIx
pattern QueryDoT         = StatsIx 58
pattern QueryDoH2       :: StatsIx
pattern QueryDoH2        = StatsIx 59
pattern QueryDoH2C      :: StatsIx
pattern QueryDoH2C       = StatsIx 60
pattern QueryDoQ        :: StatsIx
pattern QueryDoQ         = StatsIx 61
pattern QueryDoH3       :: StatsIx
pattern QueryDoH3        = StatsIx 62

pattern AcceptedTCP53   :: StatsIx
pattern AcceptedTCP53    = StatsIx 63
pattern AcceptedDoT     :: StatsIx
pattern AcceptedDoT      = StatsIx 64
pattern AcceptedDoH2    :: StatsIx
pattern AcceptedDoH2     = StatsIx 65
pattern AcceptedDoH2C   :: StatsIx
pattern AcceptedDoH2C    = StatsIx 66
pattern AcceptedDoQ     :: StatsIx
pattern AcceptedDoQ      = StatsIx 67
pattern AcceptedDoH3    :: StatsIx
pattern AcceptedDoH3     = StatsIx 68

pattern CurConnTCP53    :: StatsIx
pattern CurConnTCP53     = StatsIx 69
pattern CurConnDoT      :: StatsIx
pattern CurConnDoT       = StatsIx 70
pattern CurConnDoH2     :: StatsIx
pattern CurConnDoH2      = StatsIx 71
pattern CurConnDoH2C    :: StatsIx
pattern CurConnDoH2C     = StatsIx 72
pattern CurConnDoQ      :: StatsIx
pattern CurConnDoQ       = StatsIx 73
pattern CurConnDoH3     :: StatsIx
pattern CurConnDoH3      = StatsIx 74

pattern IxLabledMax     :: StatsIx
pattern IxLabledMax      = StatsIx 74

pattern HistogramMin    :: StatsIx
pattern HistogramMin     = StatsIx 75
pattern HistogramMax    :: StatsIx
pattern HistogramMax     = StatsIx 114
pattern QTimeSumUsec    :: StatsIx
pattern QTimeSumUsec     = StatsIx 115

pattern StatsIxMax      :: StatsIx
pattern StatsIxMax       = StatsIx 115
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
labels :: Array StatsIx Builder
labels = array (StatsIxMin, StatsIxMax) [
    (CacheHit,         "cache_hits_total")
  , (CacheMiss,        "cache_misses_total")
  , (ResolveDenied,    "unwanted_queries_total")
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
  --
  , (QueriesAll,       "queries_total")
  --
  , (QueryIPv4,        "query_ipv4_total")
  , (QueryIPv6,        "query_ipv6_total")
  --
  , (QueryDO,          "query_edns_DO_total")
  --
  , (QueryTCP,         "query_tcp_total")
  , (QueryTLS,         "query_tls_total")
  , (QueryHTTPS,       "query_https_total")
  , (QueryQUIC,        "query_quic_total")
  , (QueryHTTP3,       "query_http3_total")
  --
  , (QueryUDP53,       "query_udp53_total")
  , (QueryTCP53,       "query_tcp53_total")
  , (QueryDoT,         "query_dot_total")
  , (QueryDoH2,        "query_doh2_total")
  , (QueryDoH2C,       "query_doh2c_total")
  , (QueryDoQ,         "query_doq_total")
  , (QueryDoH3,        "query_doh3_total")
  --
  , (AcceptedTCP53,    "accepted_tcp53_total")
  , (AcceptedDoT,      "accepted_dot_total")
  , (AcceptedDoH2,     "accepted_doh2_total")
  , (AcceptedDoH2C,    "accepted_doh2c_total")
  , (AcceptedDoQ,      "accepted_doq_total")
  , (AcceptedDoH3,     "accepted_doh3_total")
  --
  , (CurConnTCP53,     "connection_tcp53_current")
  , (CurConnDoT,       "connection_dot_current")
  , (CurConnDoH2,      "connection_doh2_current")
  , (CurConnDoH2C,     "connection_doh2c_current")
  , (CurConnDoQ,       "connection_doq_current")
  , (CurConnDoH3,      "connection_doh3_current")
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

modifyStats :: (Int -> Int) -> Stats -> StatsIx -> IO ()
modifyStats modify (Stats stats) ix = do
    (i, _) <- myThreadId >>= threadCapability
    void $ atomicModifyIntArray (stats ! i) ix modify

incStats :: Stats -> StatsIx -> IO ()
incStats = modifyStats succ

decStats :: Stats -> StatsIx -> IO ()
decStats = modifyStats pred  {- thread may runs on the other capability, so negative Int value is possible -}

incStatsM :: Ord a => Stats -> Map a StatsIx -> a -> Maybe StatsIx -> IO ()
incStatsM s m k mk = do
    case Map.lookup k m of
        Nothing -> case mk of
            Nothing -> return ()
            Just dx -> incStats s dx
        Just ix -> incStats s ix

foldStats :: StatsIx -> StatsIx -> Stats -> (b -> StatsIx -> Int -> b) -> b -> IO b
foldStats lower upper (Stats stats) cons nil = do
    n <- getNumCapabilities
    go n lower nil
  where
    go n ix b
        | ix > upper = return b
        | otherwise = do
            v <- sumup 0 n ix 0
            let b' = cons b ix v
            go n (succ ix) b'
    sumup :: Int -> Int -> StatsIx -> Int -> IO Int
    sumup i n ix acc
        | i < n = do
            v <- readArray (stats ! i) ix
            sumup (i + 1) n ix (acc + v)
        | otherwise = return acc

readStats :: Stats -> Builder -> IO Builder
readStats stats prefix = foldStats StatsIxMin IxLabledMax stats step mempty
  where
    toB :: Int -> Builder
    toB = lazyByteString . BL.pack . show
    step b ix v = b <> prefix <> (labels ! ix) <> " " <> toB v <> "\n"

readHistogram :: Stats -> IO [Int]
readHistogram stats = foldStats HistogramMin HistogramMax stats (\hs _ix v -> hs . (v:)) id <&> ($ [])

readQueryTimeSumUsec :: Stats -> IO Int
readQueryTimeSumUsec stats = foldStats QTimeSumUsec QTimeSumUsec stats (\_ _ix v -> v) 0

---

{- FOURMOLU_DISABLE -}
incOnPeerAddr :: SockAddr -> Stats -> IO a -> IO a
incOnPeerAddr sa stats act = case sa of
    SockAddrInet{}   -> incStats stats QueryIPv4 *> act
    SockAddrInet6{}  -> incStats stats QueryIPv6 *> act
    SockAddrUnix{}   -> act
{- FOURMOLU_ENABLE -}

incStatsDoX :: [StatsIx] -> SockAddr -> Stats -> IO ()
incStatsDoX ixs sa stats = incOnPeerAddr sa stats (mapM_ (incStats stats) ixs)

incStatsUDP53 :: SockAddr -> Stats -> IO ()
incStatsUDP53 = incStatsDoX [QueryUDP53]

incStatsTCP53 :: SockAddr -> Stats -> IO ()
incStatsTCP53 = incStatsDoX [QueryTCP53, QueryTCP]

incStatsDoT :: SockAddr -> Stats -> IO ()
incStatsDoT = incStatsDoX [QueryDoT, QueryTLS, QueryTCP]

incStatsDoH2 :: SockAddr -> Stats -> IO ()
incStatsDoH2 = incStatsDoX [QueryDoH2, QueryHTTPS, QueryTLS, QueryTCP]

incStatsDoH2C :: SockAddr -> Stats -> IO ()
incStatsDoH2C = incStatsDoX [QueryDoH2C, QueryTCP]

incStatsDoQ :: SockAddr -> Stats -> IO ()
incStatsDoQ = incStatsDoX [QueryDoQ, QueryQUIC]

incStatsDoH3 :: SockAddr -> Stats -> IO ()
incStatsDoH3 = incStatsDoX [QueryDoH3, QueryHTTP3, QueryQUIC]

---

sessionStatsDoX :: [StatsIx] -> [StatsIx] -> Stats -> IO () -> IO ()
sessionStatsDoX accepted curr stats = E.bracket_ (mapM_ (incStats stats) $ accepted ++ curr) (mapM_ (decStats stats) curr)

sessionStatsTCP53 :: Stats -> IO () -> IO ()
sessionStatsTCP53 = sessionStatsDoX [AcceptedTCP53] [CurConnTCP53]

sessionStatsDoT :: Stats -> IO () -> IO ()
sessionStatsDoT = sessionStatsDoX [AcceptedDoT] [CurConnDoT]

sessionStatsDoH2 :: Stats -> IO () -> IO ()
sessionStatsDoH2 = sessionStatsDoX [AcceptedDoH2] [CurConnDoH2]

sessionStatsDoH2C :: Stats -> IO () -> IO ()
sessionStatsDoH2C = sessionStatsDoX [AcceptedDoH2C] [CurConnDoH2C]

sessionStatsDoQ :: Stats -> IO () -> IO ()
sessionStatsDoQ = sessionStatsDoX [AcceptedDoQ] [CurConnDoQ]

{- NOTE: not applied to Server/HTTP3 modules that cannot handle connections. -}
sessionStatsDoH3 :: Stats -> IO () -> IO ()
sessionStatsDoH3 = sessionStatsDoX [AcceptedDoH3] [CurConnDoH3]

---

bucketUpperBounds :: [(Int64, Int64)]
bucketUpperBounds =
      [ (0, u) | u <- pow19s ] ++ [ (s, 0) | s <- pow19s ]
    where
      pow19s = [ 2^n | n <- [ 0 :: Int .. 19 ] ]

bucketUpperArray :: UArray StatsIx Int64
bucketUpperArray =
    listArray (HistogramMin, HistogramMax) micros
  where
    micros = [s * 1_000_000 + u | (s, u) <- bucketUpperBounds ]

{- FOURMOLU_DISABLE -}
withPositiveInt64Usec :: Integer -> a -> (Int64 -> a) -> a
withPositiveInt64Usec int nothing just
    | int < 0       = nothing
    | int > maxI64  = nothing
    | otherwise     = just (fromIntegral int)
  where
    maxI64 = fromIntegral (maxBound :: Int64)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
runBucketUsec :: Int64 -> a -> (StatsIx -> a) -> a
runBucketUsec d64 nothing just = go HistogramMin
  where
    go ix
        | ix > HistogramMax             = nothing
        | d64 <= bucketUpperArray ! ix  = just ix
        | otherwise                     = go (succ ix)
{- FOURMOLU_ENABLE -}

addQueryTimeSumUsec :: Int64 -> Stats -> IO ()
addQueryTimeSumUsec d64 stats = modifyStats (fromIntegral d64 +) stats QTimeSumUsec

{- FOURMOLU_DISABLE -}
getUpdateHistogram :: IO () -> IO (Integer -> Stats -> IO ())
getUpdateHistogram notSupportLog = do
    addQueryTimeSum <- getAddSumAction
    pure $ \duration stats -> withPositiveInt64Usec duration (pure ()) $ \d64 -> do
        runBucketUsec d64 (pure ()) (incStats stats)
        addQueryTimeSum d64 stats
  where
    getAddSumAction {- only support for Int64 -}
        | intMax >= int64Max  = pure addQueryTimeSumUsec
        | otherwise           = notSupportLog $> \_ _ -> pure ()
    intMax    = fromIntegral (maxBound :: Int) :: Integer
    int64Max  = fromIntegral (maxBound :: Int64) :: Integer
{- FOURMOLU_ENABLE -}
