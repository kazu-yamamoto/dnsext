module DNS.Types.Time (
    EpochTime,
    getCurrentTime,
    getCurrentTimeNsec,
) where

import Data.Int (Int64)
import Data.UnixTime
import Foreign.C.Types (CTime (..))

type EpochTime = Int64

getCurrentTime :: IO EpochTime
getCurrentTime = do
    UnixTime (CTime tim) _ <- getUnixTime
    return tim

getCurrentTimeNsec :: IO (EpochTime, Int64)
getCurrentTimeNsec = do
    UnixTime (CTime tim) usec <- getUnixTime
    return (tim, fromIntegral usec * 1000)
