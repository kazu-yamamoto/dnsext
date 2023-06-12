{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module DNS.SEC.Time where

import DNS.SEC.Imports
import DNS.Types.Internal
import qualified Data.ByteString.Char8 as C8
import Data.Int (Int64)
import Data.UnixTime
import Foreign.C.Types (CTime (..))

newtype DNSTime = DNSTime {fromDNSTime :: Int64} deriving (Eq, Ord, Num)

toDNSTime :: Int64 -> DNSTime
toDNSTime = DNSTime

instance Show DNSTime where
    show (DNSTime i32) = C8.unpack $ formatUnixTimeGMT webDateFormat $ UnixTime (CTime i32) 0

-- | Given a 32-bit circle-arithmetic DNS time, and the current absolute epoch
-- time, return the epoch time corresponding to the DNS timestamp.
dnsTime
    :: Word32
    -- ^ DNS circle-arithmetic timestamp
    -> EpochTime
    -- ^ current epoch time
    -> DNSTime
    -- ^ absolute DNS timestamp
dnsTime tdns tnow =
    let delta = tdns - fromIntegral tnow
     in if delta > 0x7FFFFFFF -- tdns is in the past?
            then DNSTime (tnow - (0x100000000 - fromIntegral delta))
            else DNSTime (tnow + fromIntegral delta)

-- | Helper to find position of RData end, that is, the offset of the first
-- byte /after/ the current RData.
getDNSTime :: SGet DNSTime
getDNSTime = do
    tnow <- getAtTime
    tdns <- get32
    return $ dnsTime tdns tnow

putDNSTime :: DNSTime -> SPut ()
putDNSTime (DNSTime i32) = put32 $ fromIntegral i32
