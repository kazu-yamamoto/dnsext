{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.TimeCache (
    TimeCache (..),
    newTimeCache,
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
import Control.AutoUpdate
import Control.AutoUpdate.Internal (mkClosableAutoUpdate)

{- FOURMOLU_DISABLE -}
data TimeCache = TimeCache
    { getTime         :: IO EpochTime
    , getTimeStr      :: IO ShowS
    , closeTimeCache  :: IO ()
    }
{- FOURMOLU_ENABLE -}

newTimeCache :: IO TimeCache
newTimeCache = do
    let settings0 =
            defaultUpdateSettings
                { updateFreq = 1_000_000
                , updateAction = getUnixTime
                , updateThreadName = "dnsext-utils: AutoUpdate for getUnixTime"
                }
    (onceGetTime, close1) <- mkClosableAutoUpdate settings0
    let settings1 =
            defaultUpdateSettings
                { updateFreq = 1_000_000
                , updateAction = getTimeShowS =<< onceGetTime
                , updateThreadName = "dnsext-utils: AutoUpdate for onceGetTime"
                }
    (onceGetString, close2) <- mkClosableAutoUpdate settings1
    return $ TimeCache (unixToEpoch <$> onceGetTime) onceGetString (close2 >> close1)

noneTimeCache :: TimeCache
noneTimeCache =
    TimeCache
        { getTime = unixToEpoch <$> getUnixTime
        , getTimeStr = getTimeShowS =<< getUnixTime
        , closeTimeCache = pure ()
        }

---

getTimeShowS :: UnixTime -> IO ShowS
getTimeShowS ts = (++) . C8.unpack <$> formatUnixTime "%Y-%m-%d %H:%M:%S %Z" ts

unixToEpoch :: UnixTime -> EpochTime
unixToEpoch (UnixTime (CTime tim) _) = tim
