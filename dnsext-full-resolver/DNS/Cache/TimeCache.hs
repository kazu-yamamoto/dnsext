module DNS.Cache.TimeCache (
    TimeCache(..),
    newTimeCache,
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

-- dnsext packages
import Data.UnixTime (UnixTime (..), formatUnixTime, getUnixTime)

-- this package
import DNS.Cache.Imports

data TimeCache = TimeCache
    { getTime :: IO EpochTime
    , getTimeStr :: IO ShowS
    }

newTimeCache :: IO TimeCache
newTimeCache = do
    getUTime <- mkAutoUnixTime
    TimeCache <$> mkAutoSeconds getUTime <*> mkAutoTimeShowS getUTime

mkAutoUnixTime :: IO (IO UnixTime)
mkAutoUnixTime = mostOncePerSecond getUnixTime

mkAutoSeconds :: IO UnixTime -> IO (IO EpochTime)
mkAutoSeconds getUTime = mostOncePerSecond $ unixToEpoch <$> getUTime

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
noneTimeCache = TimeCache
    { getTime = unixToEpoch <$> getUnixTime
    , getTimeStr = getTimeShowS =<< getUnixTime
    }

---

getTimeShowS :: UnixTime -> IO ShowS
getTimeShowS ts = (++) . C8.unpack <$> formatUnixTime (fromString "%Y-%m-%d %H:%M:%S %Z") ts

unixToEpoch :: UnixTime -> EpochTime
unixToEpoch (UnixTime (CTime tim) _) = tim
