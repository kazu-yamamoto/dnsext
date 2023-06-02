module DNS.SEC.Time where

import DNS.Types.Internal

import DNS.SEC.Imports

-- | Given a 32-bit circle-arithmetic DNS time, and the current absolute epoch
-- time, return the epoch time corresponding to the DNS timestamp.
--
dnsTime :: Word32    -- ^ DNS circle-arithmetic timestamp
        -> EpochTime -- ^ current epoch time
        -> DNSTime   -- ^ absolute DNS timestamp
dnsTime tdns tnow =
    let delta = tdns - fromIntegral tnow
     in if delta > 0x7FFFFFFF -- tdns is in the past?
           then tnow - (0x100000000 - fromIntegral delta)
           else tnow + fromIntegral delta

-- | Helper to find position of RData end, that is, the offset of the first
-- byte /after/ the current RData.
--
getDNSTime :: SGet DNSTime
getDNSTime   = do
    tnow <- getAtTime
    tdns <- get32
    return $ dnsTime tdns tnow

putDNSTime :: DNSTime -> SPut ()
putDNSTime = put32 . fromIntegral
