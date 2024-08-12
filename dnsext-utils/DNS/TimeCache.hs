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
import DNS.Utils.AutoUpdate (mkClosableAutoUpdate)

{- FOURMOLU_DISABLE -}
data TimeCache = TimeCache
    { getTime         :: IO EpochTime
    , getTimeStr      :: IO ShowS
    , closeTimeCache  :: IO ()
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
newTimeCache :: Int -> IO TimeCache
newTimeCache _micros = do
    let interval = 1_000_000
    (onceGetTime  , close1) <- mkClosableAutoUpdate interval  getUnixTime
    (onceGetString, close2) <- mkClosableAutoUpdate interval (getTimeShowS =<< onceGetTime)
    return $ TimeCache (unixToEpoch <$> onceGetTime) onceGetString (close2 >> close1)
{- FOURMOLU_ENABLE -}

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
