{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module DNS.Iterative.Stats where

import Control.Concurrent
import Control.Monad
import DNS.Array
import Data.Array
import Data.Array.IO
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy.Char8 as BL

newtype StatsIx = StatsIx Int deriving (Eq,Ord,Enum,Ix)

pattern StatsIxMin  :: StatsIx
pattern StatsIxMin   = StatsIx 0
pattern CacheHit    :: StatsIx
pattern CacheHit     = StatsIx 0
pattern CacheMiss   :: StatsIx
pattern CacheMiss    = StatsIx 1
pattern CacheFailed :: StatsIx
pattern CacheFailed  = StatsIx 2
pattern StatsIxMax  :: StatsIx
pattern StatsIxMax   = StatsIx 2

labels :: Array StatsIx Builder
labels = array (StatsIxMin, StatsIxMax) [
    (CacheHit,    "cache_hit")
  , (CacheMiss,   "cache_miss")
  , (CacheFailed, "cache_failed")
  ]

newtype Stats = Stats (Array Int (IOUArray StatsIx Int))

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
            let b' = b <> prefix <> (labels ! ix) <> toB v <> "\n"
            go n (succ ix) b'
    sumup :: Int -> Int -> StatsIx -> Int -> IO Int
    sumup i n ix acc
      | i < n = do
          v <- readArray (stats ! i) ix
          sumup (i + 1) n ix (acc + v)
      | otherwise = return acc
