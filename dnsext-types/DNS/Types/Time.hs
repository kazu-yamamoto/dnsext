{-# LANGUAGE NumericUnderscores #-}

module DNS.Types.Time (
    EpochTime,
    EpochTimeUsec,
    getCurrentTime,
    getCurrentTimeUsec,
    runEpochTimeUsec,
    epochUsecToSeconds,
    diffUsec,
    getCurrentTimeNsec,
) where

import Data.Int (Int32, Int64)
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

runEpochTimeUsec :: EpochTimeUsec -> (Int64 -> Int32 -> a) -> a
runEpochTimeUsec (UnixTime (CTime sec) usec) f = f sec usec

epochUsecToSeconds :: EpochTimeUsec -> EpochTime
epochUsecToSeconds (UnixTime (CTime tim) _) =  tim

diffUsec :: EpochTimeUsec -> EpochTimeUsec -> Integer
diffUsec x y = toMicro $ diffUnixTime x y
  where
    toMicro (UnixDiffTime (CTime sec) u) = fromIntegral sec * 1_000_000 + fromIntegral u

getCurrentTimeNsec :: IO (EpochTime, Int64)
getCurrentTimeNsec = do
    UnixTime (CTime tim) usec <- getUnixTime
    return (tim, fromIntegral usec * 1000)
