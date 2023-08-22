module DNS.Cache.TimeCache (
    new,
    none,
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

new :: IO (IO EpochTime, IO ShowS)
new = do
    getUTime <- mkAutoUnixTime
    getSec <- mkAutoSeconds getUTime
    getShowS <- mkAutoTimeShowS getUTime
    pure (getSec, getShowS)

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

none :: (IO EpochTime, IO ShowS)
none = (unixToEpoch <$> getUnixTime, getTimeShowS =<< getUnixTime)

---

getTimeShowS :: UnixTime -> IO ShowS
getTimeShowS ts = (++) . C8.unpack <$> formatUnixTime (fromString "%Y-%m-%d %H:%M:%S %Z") ts

unixToEpoch :: UnixTime -> EpochTime
unixToEpoch (UnixTime (CTime tim) _) = tim
