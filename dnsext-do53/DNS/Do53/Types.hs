{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- | Resolver related data types.
module DNS.Do53.Types (
  -- * Configuration for resolver
    ResolvConf(..)
  , defaultResolvConf
  , LookupEnv(..)
  -- ** Specifying DNS servers
  , FileOrNumericHost(..)
  -- ** Configuring cache
  , CacheConf(..)
  , defaultCacheConf
  -- * Type and function for resolver
  , ResolvEnv(..)
  , ResolvInfo(..)
  , defaultResolvInfo
  , Resolver
  ) where

import DNS.Types
import DNS.Types.Decode
import Network.Socket (HostName, PortNumber, HostName, PortNumber)
import Prelude
import System.Timeout (timeout)

import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Query

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
    maximumTTL   :: TTL
    -- | If RR's TTL is lower than this value, this value is used instead.
  , minimumTTL   :: TTL
    -- | Cache pruning interval in seconds.
  , pruningDelay :: Int
  } deriving Show

-- | Default cache configuration.
--
-- >>> defaultCacheConf
-- CacheConf {maximumTTL = 300(5 mins), minimumTTL = 0(secs), pruningDelay = 10}
defaultCacheConf :: CacheConf
defaultCacheConf = CacheConf 300 0 10

----------------------------------------------------------------

-- | Type for resolver configuration.
--  Use 'defaultResolvConf' to create a new value.
--
--  An example to use Google's public DNS cache instead of resolv.conf:
--
--  > let conf = defaultResolvConf { resolvInfo = RCHostName "8.8.8.8" }
--
--  An example to use multiple Google's public DNS cache concurrently:
--
--  > let conf = defaultResolvConf { resolvInfo = RCHostNames ["8.8.8.8","8.8.4.4"], resolvConcurrent = True }
--
--  An example to disable EDNS:
--
--  > let conf = defaultResolvConf { resolvQueryControls = ednsEnabled FlagClear }
--
--  An example to enable query result caching:
--
--  > let conf = defaultResolvConf { resolvCache = Just defaultCacheConf }
--
-- An example to disable requesting recursive service.
--
--  > let conf = defaultResolvConf { resolvQueryControls = rdFlag FlagClear }
--
-- An example to set the AD bit in all queries by default.
--
--  > let conf = defaultResolvConf { resolvQueryControls = adFlag FlagSet }
--
-- An example to set the both the AD and CD bits in all queries by default.
--
--  > let conf = defaultResolvConf { resolvQueryControls = adFlag FlagSet <> cdFlag FlagSet }
--
-- An example with an EDNS buffer size of 1216 bytes, which is more robust with
-- IPv6, and the DO bit set to request DNSSEC responses.
--
--  > let conf = defaultResolvConf { resolvQueryControls = ednsSetUdpSize (Just 1216) <> doFlag FlagSet }
--
data ResolvConf = ResolvConf {
   -- | Server information.
    resolvInfo          :: FileOrNumericHost
   -- | Timeout in micro seconds.
  , resolvTimeout       :: Int
   -- | The number of UDP retries including the first try.
  , resolvRetry         :: Int
   -- | Concurrent queries if multiple DNS servers are specified.
  , resolvConcurrent    :: Bool
   -- | Cache configuration.
  , resolvCacheConf     :: Maybe CacheConf
   -- | Overrides for the default flags used for queries via resolvers that use
   -- this configuration.
  , resolvQueryControls :: QueryControls
   -- | Action to get an epoch time.
  , resolvGetTime       :: IO EpochTime
   -- | Action for timeout used with 'resolvTimeout'.
  , resolvTimeoutAction :: Int -> IO DNSMessage -> IO (Maybe DNSMessage)
}


-- | Return a default 'ResolvConf':
--
-- * 'resolvInfo' is 'RCFilePath' \"\/etc\/resolv.conf\".
-- * 'resolvTimeout' is 3,000,000 micro seconds.
-- * 'resolvRetry' is 3.
-- * 'resolvConcurrent' is False.
-- * 'resolvCacheConf' is Nothing.
-- * 'resolvQueryControls' is an empty set of overrides.
defaultResolvConf :: ResolvConf
defaultResolvConf = ResolvConf {
    resolvInfo          = RCFilePath "/etc/resolv.conf"
  , resolvTimeout       = 3 * 1000 * 1000
  , resolvRetry         = 3
  , resolvConcurrent    = False
  , resolvCacheConf     = Nothing
  , resolvQueryControls = mempty
  , resolvGetTime       = getEpochTime
  , resolvTimeoutAction = timeout
}

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver.
--   This includes newly seeded identifier generators for all
--   specified DNS servers and a cache database.
data LookupEnv = LookupEnv {
    lenvCache         :: Maybe (Cache, CacheConf)
  , lenvQueryControls :: QueryControls
  , lenvResolvEnv     :: ResolvEnv
}

data ResolvEnv = ResolvEnv {
    renvResolver    :: Resolver
  , renvConcurrent  :: Bool
  , renvResolvInfos :: [ResolvInfo]
  }

----------------------------------------------------------------

-- | Information for resolvers.
data ResolvInfo = ResolvInfo {
    rinfoHostName      :: HostName
  , rinfoPortNumber    :: PortNumber
  , rinfoGenId         :: IO Identifier
  -- share part
  , rinfoTimeout       :: IO DNSMessage -> IO (Maybe DNSMessage)
  , rinfoGetTime       :: IO EpochTime
  }

defaultResolvInfo :: ResolvInfo
defaultResolvInfo = ResolvInfo {
    rinfoHostName      = "127.0.0.1"
  , rinfoPortNumber    = 53
  , rinfoGenId         = return 0
  , rinfoTimeout       = timeout 3000000
  , rinfoGetTime       = getEpochTime
  }

-- | The type of resolvers (DNS over X).
type Resolver = ResolvInfo -> Question -> QueryControls -> IO DNSMessage
