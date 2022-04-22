module DNSC.TimeCache (
  new,
  none,
  ) where

import Control.Concurrent (threadDelay)
import Data.Int (Int64)
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Time (defaultTimeLocale, formatTime, getCurrentTimeZone, utcToZonedTime)
import Data.Time.Clock.System (SystemTime (..), getSystemTime, systemToUTCTime)

import DNSC.Concurrent (forkLoop)


new :: IO ((IO Int64, IO String), IO ())
new = do
  secRef <- newIORef 0
  formatRef <- newIORef mempty

  let step = do
        t <- getSystemTime  {- calls clock_gettime in x86-64 linux -}
        zt <- utcToZonedTime <$> getCurrentTimeZone <*> pure (systemToUTCTime t)
        let seconds = systemSeconds t
            fstring = formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S %Z" zt
            intervalUSec = 1 * 1000 * 1000 - fromIntegral (systemNanoseconds t `quot` 1000)
        writeIORef secRef seconds
        fstring `seq` writeIORef formatRef fstring
        threadDelay intervalUSec

  quit <- forkLoop step

  return ((readIORef secRef, readIORef formatRef), quit)

-- no caching
none :: (IO Int64, IO String)
none =
  (systemSeconds <$> getSystemTime,
   formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S %Z" <$> getUTC)
  where
    getUTC = utcToZonedTime <$> getCurrentTimeZone <*> fmap systemToUTCTime getSystemTime
