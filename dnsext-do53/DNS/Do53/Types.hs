{-# LANGUAGE OverloadedStrings #-}

-- | Resolver related data types.
module DNS.Do53.Types (
  -- * Configuration for resolver
    LookupConf(..)
  , defaultLookupConf
  , UDPRetry
  , VCLimit
  , LookupEnv(..)
  -- ** Specifying DNS servers
  , Seeds(..)
  -- ** Configuring cache
  , CacheConf(..)
  , defaultCacheConf
  -- * Type and function for resolver
  , ResolvEnv(..)
  , ResolvInfo(..)
  , defaultResolvInfo
  , ResolvActions(..)
  , defaultResolvActions
  , Result(..)
  , Reply(..)
  , Resolver
  -- * IO
  , Recv
  , RecvN
  , RecvMany
  , RecvManyN
  , Send
  , SendMany
  ) where

import DNS.Types
import DNS.Types.Decode
import Network.Socket (HostName, PortNumber, HostName, PortNumber)
import Prelude
import System.Timeout (timeout)

import DNS.Do53.Id
import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Query

----------------------------------------------------------------

-- | The type to specify a cache server.
data Seeds = SeedsFilePath FilePath -- ^ A path for \"resolv.conf\"
                                             -- where one or more IP addresses
                                             -- of DNS servers should be found
                                             -- on Unix.
                                             -- Default DNS servers are
                                             -- automatically detected
                                             -- on Windows regardless of
                                             -- the value of the file name.
           | SeedsHostName HostName -- ^ A numeric IP address. /Warning/: host names are invalid.
           | SeedsHostNames [HostName] -- ^ Numeric IP addresses. /Warning/: host names are invalid.
           | SeedsHostPort HostName PortNumber -- ^ A numeric IP address and port number. /Warning/: host names are invalid.
           | SeedsHostPorts [(HostName,PortNumber)]
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

type UDPRetry = Int
type VCLimit = Int

-- | Type for resolver configuration.
--  Use 'defaultLookupConf' to create a new value.
--
--  An example to use Google's public DNS cache instead of resolv.conf:
--
--  > let conf = defaultLookupConf { lconfInfo = RCHostName "8.8.8.8" }
--
--  An example to use multiple Google's public DNS cache concurrently:
--
--  > let conf = defaultLookupConf { lconfInfo = RCHostNames ["8.8.8.8","8.8.4.4"], lconfConcurrent = True }
--
--  An example to disable EDNS:
--
--  > let conf = defaultLookupConf { lconfQueryControls = ednsEnabled FlagClear }
--
--  An example to enable query result caching:
--
--  > let conf = defaultLookupConf { lconfCache = Just defaultCacheConf }
--
-- An example to disable requesting recursive service.
--
--  > let conf = defaultLookupConf { lconfQueryControls = rdFlag FlagClear }
--
-- An example to set the AD bit in all queries by default.
--
--  > let conf = defaultLookupConf { lconfQueryControls = adFlag FlagSet }
--
-- An example to set the both the AD and CD bits in all queries by default.
--
--  > let conf = defaultLookupConf { lconfQueryControls = adFlag FlagSet <> cdFlag FlagSet }
--
-- An example with an EDNS buffer size of 1216 bytes, which is more robust with
-- IPv6, and the DO bit set to request DNSSEC responses.
--
--  > let conf = defaultLookupConf { lconfQueryControls = ednsSetUdpSize (Just 1216) <> doFlag FlagSet }
--
data LookupConf = LookupConf {
   -- | Server information.
    lconfSeeds         :: Seeds
   -- | The number of UDP retries including the first try.
  , lconfRetry         :: UDPRetry
   -- | How many bytes are allowed to be received on a virtual circuit.
  , lconfLimit         :: VCLimit
   -- | Concurrent queries if multiple DNS servers are specified.
  , lconfConcurrent    :: Bool
   -- | Cache configuration.
  , lconfCacheConf     :: Maybe CacheConf
   -- | Overrides for the default flags used for queries via resolvers that use
   -- this configuration.
  , lconfQueryControls :: QueryControls
   -- | Actions for resolvers.
  , lconfActions       :: ResolvActions
}


-- | Return a default 'LookupConf':
--
-- * 'lconfSeeds' is 'SeedsFilePath' \"\/etc\/resolv.conf\".
-- * 'lconfRetry' is 3.
-- * 'lconfConcurrent' is False.
-- * 'lconfCacheConf' is Nothing.
-- * 'lconfQueryControls' is an empty set of overrides.
defaultLookupConf :: LookupConf
defaultLookupConf = LookupConf {
    lconfSeeds         = SeedsFilePath "/etc/resolv.conf"
  , lconfRetry         = 3
  , lconfLimit         = 32 * 1024
  , lconfConcurrent    = False
  , lconfCacheConf     = Nothing
  , lconfQueryControls = mempty
  , lconfActions       = defaultResolvActions
}

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver.
--   This includes newly seeded identifier generators for all
--   specified DNS servers and a cache database.
data LookupEnv = LookupEnv {
    lenvCache         :: Maybe (Memo, CacheConf)
  , lenvQueryControls :: QueryControls
  , lenvConcurrent    :: Bool
  , lenvResolvEnv     :: ResolvEnv
  , lenvActions       :: ResolvActions -- for cache lookup
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
  , rinfoActions       :: ResolvActions
  , rinfoDebug         :: Bool
  }

defaultResolvInfo :: ResolvInfo
defaultResolvInfo = ResolvInfo {
    rinfoHostName      = "127.0.0.1"
  , rinfoPortNumber    = 53
  , rinfoActions       = defaultResolvActions
  , rinfoDebug         = False
  }

data Result = Result {
    resultHostName   :: HostName
  , resultPortNumber :: PortNumber
  , resultTag        :: String
  , resultReply      :: Reply
  } deriving (Eq, Show)

data Reply = Reply {
    replyDNSMessage :: DNSMessage
  , replyTxBytes    :: Int
  , replyRxBytes    :: Int
  } deriving (Eq, Show)

-- | The type of resolvers (DNS over X).
type Resolver = ResolvInfo -> Question -> QueryControls -> IO Result

----------------------------------------------------------------

data ResolvActions = ResolvActions {
    ractionTimeout :: IO Reply -> IO (Maybe Reply)
  , ractionGenId   :: IO Identifier
  , ractionGetTime :: IO EpochTime
  }

defaultResolvActions :: ResolvActions
defaultResolvActions = ResolvActions {
    ractionTimeout = timeout 3000000
  , ractionGenId   = singleGenId
  , ractionGetTime = getEpochTime
  }

----------------------------------------------------------------

type Recv      = IO ByteString
type RecvN     = Int -> IO ByteString
type RecvMany  = IO (Int, [ByteString])
type RecvManyN = Int -> IO (Int, [ByteString])

type Send = ByteString -> IO ()
type SendMany = [ByteString] -> IO ()
