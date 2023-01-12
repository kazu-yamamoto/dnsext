module DNS.Cache.DNSUtil (
  lookupRaw,

  -- interfaces to check compile-time configs
  ) where

-- dns packages
import qualified DNS.Do53.Client as DNS
import DNS.Types (DNSMessage)
import qualified DNS.Types as DNS
import DNS.Types.Decode (EpochTime)

---

lookupRaw :: EpochTime -> DNS.Resolver -> DNS.Domain -> DNS.TYPE -> IO (Either DNS.DNSError DNSMessage)
lookupRaw now rslv dom typ = DNS.lookupRawCtlTime rslv dom typ mempty (return now)
