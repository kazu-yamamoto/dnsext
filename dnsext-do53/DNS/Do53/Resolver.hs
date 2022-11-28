{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}

-- | Resolver related data types.
module DNS.Do53.Resolver (
  -- * Configuration for resolver
    ResolvConf(..)
  , defaultResolvConf
  -- ** Specifying DNS servers
  , FileOrNumericHost(..)
  -- ** Configuring cache
  , CacheConf(..)
  , defaultCacheConf
  -- * Type and function for resolver
  , Resolver(..)
  , withResolver
  ) where

import Control.Exception as E
import DNS.Types
import qualified Data.List.NonEmpty as NE
import Network.Socket (AddrInfoFlag(..), AddrInfo(..), PortNumber, HostName, SocketType(Datagram), getAddrInfo, defaultHints)
import Prelude
import qualified System.Random.Stateful as R

import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Query
import DNS.Do53.System

----------------------------------------------------------------

findAddresses :: ResolvConf -> IO (NonEmpty AddrInfo)
findAddresses conf = case resolvInfo conf of
    RCHostName numhost       -> (:| []) <$> makeAddrInfo numhost Nothing
    RCHostPort numhost mport -> (:| []) <$> makeAddrInfo numhost (Just mport)
    RCHostNames nss          -> mkAddrs nss
    RCFilePath file          -> getDefaultDnsServers file >>= mkAddrs
  where
    mkAddrs []     = E.throwIO BadConfiguration
    mkAddrs (l:ls) = (:|) <$> makeAddrInfo l Nothing <*> forM ls (`makeAddrInfo` Nothing)

makeAddrInfo :: HostName -> Maybe PortNumber -> IO AddrInfo
makeAddrInfo addr mport = do
    let hints = defaultHints {
            addrFlags = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_NUMERICSERV, AI_PASSIVE]
          , addrSocketType = Datagram
          }
        -- 53 is the standard port number for domain name servers as assigned by IANA
        serv = maybe "53" show mport
    head <$> getAddrInfo (Just hints) (Just addr) (Just serv)

----------------------------------------------------------------

-- | Giving a thread-safe 'Resolver' to the function of the second
--   argument.
withResolver :: ResolvConf -> (Resolver -> IO a) -> IO a
withResolver conf f = do
    addrs <- findAddresses conf
    let n = NE.length addrs
    gs <- replicateM n (R.initStdGen >>= R.newIOGenM)
    let gens = NE.fromList $ map R.uniformWord16 gs
    mcache <- case resolvCache conf of
      Just cacheconf -> Just <$> newCache (pruningDelay cacheconf)
      Nothing -> return Nothing
    let resolver = Resolver conf addrs gens mcache
    f resolver

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

-- | Abstract data type of DNS Resolver.
--   This includes newly seeded identifier generators for all
--   specified DNS servers and a cache database.
data Resolver = Resolver {
    resolvConf  :: ResolvConf
  , serverAddrs :: NonEmpty AddrInfo
  , genIds      :: NonEmpty (IO Word16)
  , cache       :: Maybe Cache
}
