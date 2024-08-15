{-# LANGUAGE NumericUnderscores #-}

module DNS.Types.Time (
    EpochTime,
    EpochTimeUsec,
    getCurrentTime,
    getCurrentTimeUsec,
    getCurrentTimeNsec,
    epochUsecToSeconds,
    diffMicroSec,
) where

import Data.Int (Int64)
import Data.UnixTime
import Foreign.C.Types (CTime (..))

type EpochTime = Int64

getCurrentTime :: IO EpochTime
getCurrentTime = do
    UnixTime (CTime tim) _ <- getUnixTime
    return tim

type EpochTimeUsec = UnixTime

getCurrentTimeUsec :: IO EpochTimeUsec
getCurrentTimeUsec = getUnixTime

epochUsecToSeconds :: EpochTimeUsec -> EpochTime
epochUsecToSeconds (UnixTime (CTime tim) _) =  tim

diffMicroSec :: EpochTimeUsec -> EpochTimeUsec -> Integer
diffMicroSec x y = toMicro $ diffUnixTime x y
  where
    toMicro (UnixDiffTime (CTime sec) u) = fromIntegral sec * 1_000_000 + fromIntegral u

getCurrentTimeNsec :: IO (EpochTime, Int64)
getCurrentTimeNsec = do
    UnixTime (CTime tim) usec <- getUnixTime
    return (tim, fromIntegral usec * 1000)
