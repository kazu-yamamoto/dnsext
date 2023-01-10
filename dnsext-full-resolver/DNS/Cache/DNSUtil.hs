module DNS.Cache.DNSUtil (
  lookupRaw,

  -- interfaces to check compile-time configs
  ) where

-- GHC packages
import Data.Int (Int64)

-- dns packages
import DNS.Types (DNSMessage)
import qualified DNS.Types as DNS
import qualified DNS.Do53.Client as DNS

---

lookupRaw :: Int64 -> DNS.Resolver -> DNS.Domain -> DNS.TYPE -> IO (Either DNS.DNSError DNSMessage)
lookupRaw now rslv dom typ = DNS.lookupRawCtlTime rslv dom typ mempty (return now)
