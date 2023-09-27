{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module DNS.Iterative.Stats where

import Control.Concurrent
import Control.Monad
import DNS.Array
import DNS.Types
import DNS.Types.Internal
import DNS.SEC
import DNS.SVCB
import Data.Array
import Data.Array.IO
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

newtype StatsIx = StatsIx Int deriving (Eq,Ord,Enum,Ix)

pattern StatsIxMin      :: StatsIx
pattern StatsIxMin       = StatsIx 0

pattern CacheHit        :: StatsIx
pattern CacheHit         = StatsIx 0
pattern CacheMiss       :: StatsIx
pattern CacheMiss        = StatsIx 1
pattern CacheFailed     :: StatsIx
pattern CacheFailed      = StatsIx 2
pattern QueryTypeRes    :: StatsIx
pattern QueryTypeRes     = StatsIx 3
pattern QueryTypeA      :: StatsIx
pattern QueryTypeA       = StatsIx 4
pattern QueryTypeA6     :: StatsIx
pattern QueryTypeA6      = StatsIx 5
pattern QueryTypeAAAA   :: StatsIx
pattern QueryTypeAAAA    = StatsIx 6
pattern QueryTypeCNAME  :: StatsIx
pattern QueryTypeCNAME   = StatsIx 7
pattern QueryTypeDNSKEY :: StatsIx
pattern QueryTypeDNSKEY  = StatsIx 8
pattern QueryTypeDS     :: StatsIx
pattern QueryTypeDS      = StatsIx 9
pattern QueryTypeHINFO  :: StatsIx
pattern QueryTypeHINFO   = StatsIx 10
pattern QueryTypeHTTPS  :: StatsIx
pattern QueryTypeHTTPS   = StatsIx 11
pattern QueryTypeMX     :: StatsIx
pattern QueryTypeMX      = StatsIx 12
pattern QueryTypeNS     :: StatsIx
pattern QueryTypeNS      = StatsIx 13
pattern QueryTypeNULL   :: StatsIx
pattern QueryTypeNULL    = StatsIx 14
pattern QueryTypePTR    :: StatsIx
pattern QueryTypePTR     = StatsIx 15
pattern QueryTypeRRSIG  :: StatsIx
pattern QueryTypeRRSIG   = StatsIx 16
pattern QueryTypeSOA    :: StatsIx
pattern QueryTypeSOA     = StatsIx 17
pattern QueryTypeSPF    :: StatsIx
pattern QueryTypeSPF     = StatsIx 18
pattern QueryTypeSRV    :: StatsIx
pattern QueryTypeSRV     = StatsIx 19
pattern QueryTypeSSHFP  :: StatsIx
pattern QueryTypeSSHFP   = StatsIx 20

pattern StatsIxMax      :: StatsIx
pattern StatsIxMax       = StatsIx 20

labels :: Array StatsIx Builder
labels = array (StatsIxMin, StatsIxMax) [
    (CacheHit,         "cache_hit")
  , (CacheMiss,        "cache_miss")
  , (CacheFailed,      "cache_failed")
  , (QueryTypeRes,     "query_types_total{type=\"Reserved\"}")
  , (QueryTypeA,       "query_types_total{type=\"A\"}")
  , (QueryTypeA6,      "query_types_total{type=\"A6\"}")
  , (QueryTypeAAAA,    "query_types_total{type=\"AAAA\"}")
  , (QueryTypeCNAME,   "query_types_total{type=\"CANME\"}")
  , (QueryTypeDNSKEY,  "query_types_total{type=\"DNSKEY\"}")
  , (QueryTypeDS,      "query_types_total{type=\"DS\"}")
  , (QueryTypeHINFO,   "query_types_total{type=\"HINFO\"}")
  , (QueryTypeHTTPS,   "query_types_total{type=\"HTTPS\"}")
  , (QueryTypeMX,      "query_types_total{type=\"MX\"}")
  , (QueryTypeNS,      "query_types_total{type=\"NS\"}")
  , (QueryTypeNULL,    "query_types_total{type=\"NULL\"}")
  , (QueryTypePTR,     "query_types_total{type=\"PTR\"}")
  , (QueryTypeRRSIG,   "query_types_total{type=\"RRSIG\"}")
  , (QueryTypeSOA,     "query_types_total{type=\"SOA\"}")
  , (QueryTypeSPF,     "query_types_total{type=\"SPF\"}")
  , (QueryTypeSRV,     "query_types_total{type=\"SRV\"}")
  , (QueryTypeSSHFP,   "query_types_total{type=\"SSHFP\"}")
  ]

newtype Stats = Stats (Array Int (IOUArray StatsIx Int))

fromQueryTypes :: Map TYPE StatsIx
fromQueryTypes = Map.fromList [
    (TYPE 0,  QueryTypeRes)
  , (A,       QueryTypeA)
  , (TYPE 38, QueryTypeA6)
  , (AAAA,    QueryTypeAAAA)
  , (CNAME,   QueryTypeCNAME)
  , (DNSKEY,  QueryTypeDNSKEY)
  , (DS,      QueryTypeDS)
  , (TYPE 13, QueryTypeHINFO)
  , (HTTPS,   QueryTypeHTTPS)
  , (MX,      QueryTypeMX)
  , (NS,      QueryTypeNS)
  , (NULL,    QueryTypeNULL)
  , (PTR,     QueryTypePTR)
  , (RRSIG,   QueryTypeRRSIG)
  , (SOA,     QueryTypeSOA)
  , (TYPE 99, QueryTypeSPF)
  , (SRV,     QueryTypeSRV)
  , (TYPE 44, QueryTypeSSHFP)
  ]

newStats :: IO Stats
newStats = do
    n <- getNumCapabilities
    Stats . listArray (0, n - 1) <$> new n
  where
    new n = sequence $ replicate n $ newArray (StatsIxMin, StatsIxMax) 0

incStats :: Stats -> StatsIx -> IO ()
incStats (Stats stats) ix = do
    (i,_) <- myThreadId >>= threadCapability
    void $ atomicModifyIntArray (stats ! i) ix (+1)

incStatsM :: Ord a => Stats -> Map a StatsIx -> a -> IO ()
incStatsM s m k = do
    case Map.lookup k m of
      Nothing -> return ()
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
