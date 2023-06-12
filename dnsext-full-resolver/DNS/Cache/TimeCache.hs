module DNS.Cache.TimeCache (
    new,
    none,
) where

-- GHC packages
import DNS.Types.Decode (EpochTime)
import Data.Time (
    defaultTimeLocale,
    formatTime,
    getCurrentTimeZone,
    utcToZonedTime,
 )
import Data.Time.Clock.System (SystemTime (..), getSystemTime, systemToUTCTime)

-- dns packages
import Control.AutoUpdate (
    defaultUpdateSettings,
    mkAutoUpdate,
    updateAction,
    updateFreq,
 )

new :: IO (IO EpochTime, IO ShowS)
new = do
    getSec <- mkAutoSeconds
    getTimeStr <- mkAutoTimeStr getSec
    return (getSec, getTimeStr)

mkAutoSeconds :: IO (IO EpochTime)
mkAutoSeconds =
    mkAutoUpdate
        defaultUpdateSettings
            { updateAction = getSystemSeconds {- calls clock_gettime in x86-64 linux -}
            , updateFreq = 1000 * 1000
            }
  where
    getSystemSeconds = do
        MkSystemTime{systemSeconds = sec} <- getSystemTime
        return sec

mkAutoTimeStr :: IO EpochTime -> IO (IO (String -> String))
mkAutoTimeStr getSec =
    mkAutoUpdate
        defaultUpdateSettings
            { updateAction = getFormattedTime
            , updateFreq = 1000 * 1000
            }
  where
    getFormattedTime = do
        sec <- getSec
        let t = MkSystemTime{systemSeconds = sec, systemNanoseconds = 0}
        zt <- utcToZonedTime <$> getCurrentTimeZone <*> pure (systemToUTCTime t)
        return (formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S %Z" zt ++)

-- no caching
none :: (IO EpochTime, IO ShowS)
none =
    ( systemSeconds <$> getSystemTime
    , (++) . formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S %Z" <$> getUTC
    )
  where
    getUTC = utcToZonedTime <$> getCurrentTimeZone <*> fmap systemToUTCTime getSystemTime
