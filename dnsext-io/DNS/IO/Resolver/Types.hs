module DNS.IO.Resolver.Types where

import Network.Socket (AddrInfo(..), PortNumber, HostName)
import DNS.Types

import DNS.IO.Imports
import DNS.IO.Memo
import DNS.IO.Query

----------------------------------------------------------------

-- | The type to specify a cache server.
data FileOrNumericHost = RCFilePath FilePath -- ^ A path for \"resolv.conf\"
                                             -- where one or more IP addresses
                                             -- of DNS servers should be found
                                             -- on Unix.
                                             -- Default DNS servers are
                                             -- automatically detected
                                             -- on Windows regardless of
                                             -- the value of the file name.
                       | RCHostName HostName -- ^ A numeric IP address. /Warning/: host names are invalid.
                       | RCHostNames [HostName] -- ^ Numeric IP addresses. /Warning/: host names are invalid.
                       | RCHostPort HostName PortNumber -- ^ A numeric IP address and port number. /Warning/: host names are invalid.
                       deriving Show

----------------------------------------------------------------

-- | Cache configuration for responses.
data CacheConf = CacheConf {
    -- | If RR's TTL is higher than this value, this value is used instead.
    maximumTTL  :: TTL
    -- | Cache pruning interval in seconds.
  , pruningDelay  :: Int
  } deriving Show

-- | Default cache configuration.
--
-- >>> defaultCacheConf
-- CacheConf {maximumTTL = 300, pruningDelay = 10}
defaultCacheConf :: CacheConf
defaultCacheConf = CacheConf 300 10

----------------------------------------------------------------

-- | Type for resolver configuration.
--  Use 'defaultResolvConf' to create a new value.
--
--  An example to use Google's public DNS cache instead of resolv.conf:
--
--  >>> let conf = defaultResolvConf { resolvInfo = RCHostName "8.8.8.8" }
--
--  An example to use multiple Google's public DNS cache concurrently:
--
--  >>> let conf = defaultResolvConf { resolvInfo = RCHostNames ["8.8.8.8","8.8.4.4"], resolvConcurrent = True }
--
--  An example to disable EDNS:
--
--  >>> let conf = defaultResolvConf { resolvQueryControls = ednsEnabled FlagClear }
--
--  An example to enable query result caching:
--
--  >>> let conf = defaultResolvConf { resolvCache = Just defaultCacheConf }
--
-- An example to disable requesting recursive service.
--
--  >>> let conf = defaultResolvConf { resolvQueryControls = rdFlag FlagClear }
--
-- An example to set the AD bit in all queries by default.
--
--  >>> let conf = defaultResolvConf { resolvQueryControls = adFlag FlagSet }
--
-- An example to set the both the AD and CD bits in all queries by default.
--
--  >>> let conf = defaultResolvConf { resolvQueryControls = adFlag FlagSet <> cdFlag FlagSet }
--
-- An example with an EDNS buffer size of 1216 bytes, which is more robust with
-- IPv6, and the DO bit set to request DNSSEC responses.
--
--  >>> let conf = defaultResolvConf { resolvQueryControls = ednsSetUdpSize (Just 1216) <> doFlag FlagSet }
--
data ResolvConf = ResolvConf {
   -- | Server information.
    resolvInfo       :: FileOrNumericHost
   -- | Timeout in micro seconds.
  , resolvTimeout    :: Int
   -- | The number of retries including the first try.
  , resolvRetry      :: Int
   -- | Concurrent queries if multiple DNS servers are specified.
  , resolvConcurrent :: Bool
   -- | Cache configuration.
  , resolvCache      :: Maybe CacheConf
   -- | Overrides for the default flags used for queries via resolvers that use
   -- this configuration.
  , resolvQueryControls :: QueryControls
} deriving Show

-- | Return a default 'ResolvConf':
--
-- * 'resolvInfo' is 'RCFilePath' \"\/etc\/resolv.conf\".
-- * 'resolvTimeout' is 3,000,000 micro seconds.
-- * 'resolvRetry' is 3.
-- * 'resolvConcurrent' is False.
-- * 'resolvCache' is Nothing.
-- * 'resolvQueryControls' is an empty set of overrides.
defaultResolvConf :: ResolvConf
defaultResolvConf = ResolvConf {
    resolvInfo       = RCFilePath "/etc/resolv.conf"
  , resolvTimeout    = 3 * 1000 * 1000
  , resolvRetry      = 3
  , resolvConcurrent = False
  , resolvCache      = Nothing
  , resolvQueryControls = mempty
}

----------------------------------------------------------------

-- | Intermediate abstract data type for resolvers.
--   IP address information of DNS servers is generated
--   according to 'resolvInfo' internally.
--   This value can be safely reused for 'withResolver'.
--
--   The naming is confusing for historical reasons.
data ResolvSeed = ResolvSeed {
    resolvconf  :: ResolvConf
  , nameservers :: NonEmpty AddrInfo
}

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver.
--   This includes newly seeded identifier generators for all
--   specified DNS servers and a cache database.
data Resolver = Resolver {
    resolvseed :: ResolvSeed
  , genIds     :: NonEmpty (IO Word16)
  , cache      :: Maybe Cache
}
