{-# LANGUAGE NumericUnderscores #-}

-- emulate prometheus histogram
module DNS.Iterative.Server.PrometheusHisto where

import Data.Int
import Data.String

import Data.ByteString.Builder (Builder)

import DNS.Iterative.Stats (Stats, bucketUpperBounds, readHistogram, readQueryTimeSumUsec)

getHistogramBucktes :: Stats -> Builder -> IO Builder
getHistogramBucktes stats_ prefix = formatBuckets prefix <$> readHistogram stats_ <*> readQueryTimeSumUsec stats_

{- FOURMOLU_DISABLE -}
formatBuckets :: Builder -> [Int] -> Int -> Builder
formatBuckets prefix hvs sumVal = mconcat $ zipWith bformat bucketUpperBounds pbackets ++ [inf_, sum_, count_]
  where
    pbackets = tail $ scanl (+) 0 hvs
    countVal
        | null pbackets  = 0
        | otherwise      = last pbackets
    bformat ub bv = prefix <> fromString ("response_time_seconds_bucket" ++ "{" ++ bucketKey ub ++ "}" ++ " " ++ show bv ++ "\n")
    inf_    = prefix <> fromString ("response_time_seconds_bucket" ++ "{\"+Inf\"}" ++ " " ++ show countVal ++ "\n")
    sum_    = prefix <> fromString ("response_time_seconds_sum" ++ " " ++ show sec ++ '.' : replicate (6 - length uss) '0' ++ uss ++ "\n")
      where
        uss = show usec
        (sec, usec) = sumVal `quotRem `1_000_000
    count_  = prefix <> fromString ("response_time_seconds_count" ++ " " ++ show countVal ++ "\n")
{- FOURMOLU_ENABLE -}

bucketKey :: (Int64, Int64) -> String
bucketKey upper = "le=" ++ ['"'] ++ bucketKey' upper ++ ['"']

{- FOURMOLU_DISABLE -}
bucketKey' :: (Int64, Int64) -> String
bucketKey' (s, u)
    | s == 0 && u <= 8   = show u ++ "e-06"
    | s == 0 && u <= 64  = show n1 ++ "." ++ show n2 ++ "e-05"
    | s == 0             = "0." ++ u6
    | otherwise          = show s
  where
    ~(n1, n2) = u `quotRem` 10
    ~u6 = replicate (6 - length su) '0' ++ su
      where su = show u
{- FOURMOLU_ENABLE -}
