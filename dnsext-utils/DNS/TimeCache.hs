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
import Control.AutoUpdate (
    defaultUpdateSettings,
    mkAutoUpdate,
    updateAction,
    updateFreq,
 )
import Data.UnixTime (UnixTime (..), formatUnixTime, getUnixTime)

-- dnsext packages
import DNS.Types.Time (EpochTime)

-- this package

{- FOURMOLU_DISABLE -}
data TimeCache = TimeCache
    { getTimestamp  :: IO UnixTime
    , getTimeStr    :: IO ShowS
    }
{- FOURMOLU_ENABLE -}

newTimeCache :: IO TimeCache
newTimeCache = do
    getUTime <- mkAutoUnixTime
    TimeCache <$> mkAutoTimestamp getUTime <*> mkAutoTimeShowS getUTime

getTime :: TimeCache -> IO EpochTime
getTime = fmap unixToEpoch . getTimestamp

mkAutoUnixTime :: IO (IO UnixTime)
mkAutoUnixTime = mostOncePerSecond getUnixTime

mkAutoTimestamp :: IO UnixTime -> IO (IO UnixTime)
mkAutoTimestamp getUTime = mostOncePerSecond getUTime

mkAutoTimeShowS :: IO UnixTime -> IO (IO ShowS)
mkAutoTimeShowS getUTime = mostOncePerSecond $ getTimeShowS =<< getUTime

mostOncePerSecond :: IO a -> IO (IO a)
mostOncePerSecond upd =
    mkAutoUpdate
        defaultUpdateSettings
            { updateAction = upd
            , updateFreq = 1000 * 1000
            }

noneTimeCache :: TimeCache
noneTimeCache =
    TimeCache
        { getTimestamp = getUnixTime
        , getTimeStr = getTimeShowS =<< getUnixTime
        }

---

getTimeShowS :: UnixTime -> IO ShowS
getTimeShowS ts = (++) . C8.unpack <$> formatUnixTime "%Y-%m-%d %H:%M:%S %Z" ts

unixToEpoch :: UnixTime -> EpochTime
unixToEpoch (UnixTime (CTime tim) _) = tim
