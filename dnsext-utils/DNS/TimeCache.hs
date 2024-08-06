{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.TimeCache (
    TimeCache (..),
    newTimeCache,
    getTime,
    noneTimeCache,
) where

-- GHC packages
import qualified Data.ByteString.Char8 as C8
import Foreign.C.Types (CTime (..))

-- other packages
import Data.UnixTime (UnixTime (..), formatUnixTime, getUnixTime)

-- dnsext-* packages
import DNS.Types.Time (EpochTime)

-- this package
import DNS.Utils.AutoUpdate (mkClosableAutoUpdate)

{- FOURMOLU_DISABLE -}
data TimeCache = TimeCache
    { getTimestamp    :: IO UnixTime
    , getTimeStr      :: IO ShowS
    , closeTimeCache  :: IO ()
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
newTimeCache :: Int -> IO TimeCache
newTimeCache micros = do
    (onceGetTime  , close1) <- mkClosableAutoUpdate micros     getUnixTime
    (onceGetString, close2) <- mkClosableAutoUpdate 1_000_000 (getTimeShowS =<< onceGetTime)
    return $ TimeCache onceGetTime onceGetString (close2 >> close1)
{- FOURMOLU_ENABLE -}

getTime :: TimeCache -> IO EpochTime
getTime = fmap unixToEpoch . getTimestamp

noneTimeCache :: TimeCache
noneTimeCache =
    TimeCache
        { getTimestamp = getUnixTime
        , getTimeStr = getTimeShowS =<< getUnixTime
        , closeTimeCache = pure ()
        }

---

getTimeShowS :: UnixTime -> IO ShowS
getTimeShowS ts = (++) . C8.unpack <$> formatUnixTime "%Y-%m-%d %H:%M:%S %Z" ts

unixToEpoch :: UnixTime -> EpochTime
unixToEpoch (UnixTime (CTime tim) _) = tim
