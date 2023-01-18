{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

-- | Resolver related data types.
module DNS.Do53.Types (
  -- * Configuration for resolver
    ResolvConf(..)
  , withResolvConf
  , Seeds(..)
  -- ** Specifying DNS servers
  , FileOrNumericHost(..)
  -- ** Configuring cache
  , CacheConf(..)
  , defaultCacheConf
  -- * Type and function for resolver
  , ResolvInfo(..)
  , defaultResolvInfo
  , Resolver
  ) where

import DNS.Types
import DNS.Types.Decode
import Network.Socket (HostName, PortNumber, HostName, PortNumber)
import Prelude
import qualified System.Random.Stateful as R
import System.Timeout (timeout)

import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Query
import DNS.Do53.System

----------------------------------------------------------------

-- 53 is the standard port number for domain name servers as assigned by IANA
dnsPort :: PortNumber
dnsPort = 53

findAddrPorts :: FileOrNumericHost -> IO [(HostName,PortNumber)]
findAddrPorts (RCHostName   nh)  = return [(nh, dnsPort)]
findAddrPorts (RCHostPort  nh p) = return [(nh, p)]
findAddrPorts (RCHostNames nss)  = return $ map (,dnsPort) nss
findAddrPorts (RCFilePath  file) = map (,dnsPort) <$> getDefaultDnsServers file

----------------------------------------------------------------

-- | Giving a thread-safe 'Seeds' to the function of the second
--   argument.
withResolvConf :: ResolvConf -> (Seeds -> IO a) -> IO a
withResolvConf rc@ResolvConf{..} f = do
    addrs <- findAddrPorts resolvInfo
    let n = length addrs
    gs <- replicateM n (R.initStdGen >>= R.newIOGenM)
    let gens = map R.uniformWord16 gs
    mcache <- case resolvCacheConf of
      Just cacheconf -> do
          cache <- newCache (pruningDelay cacheconf)
          return $ Just (cache, cacheconf)
      Nothing -> return Nothing
    let ris = makeInfo rc addrs gens
        seeds = Seeds mcache resolvResolver resolvConcurrent ris
    f seeds

makeInfo :: ResolvConf -> [(HostName, PortNumber)] -> [IO Identifier] -> [ResolvInfo]
makeInfo ResolvConf{..} hps0 gens0 = go hps0 gens0
  where
    go ((h,p):hps) (gen:gens) = ri : go hps gens
      where
        ri = ResolvInfo {
                solvHostName      = h
              , solvPortNumber    = p
              , solvGenId         = gen
              , solvTimeout       = resolvTimeoutAction resolvTimeout
              , solvGetTime       = resolvGetTime
              , solvQueryControls = resolvQueryControls
              , solvRetry         = resolvRetry
              }
    go _ _ = []

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
   -- | Resolver engine aka DNS over X.
  , resolvResolver      :: Resolver
}

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver.
--   This includes newly seeded identifier generators for all
--   specified DNS servers and a cache database.
data Seeds = Seeds {
    -- Lookup level
    seedsCache       :: Maybe (Cache, CacheConf)
    -- Resolve level
  , seedsResolver    :: Resolver
  , seedsConcurrent  :: Bool
  , seedsResolvInfos :: [ResolvInfo]
}

----------------------------------------------------------------

-- | Information for solvers.
data ResolvInfo = ResolvInfo {
    solvHostName      :: HostName
  , solvPortNumber    :: PortNumber
  , solvGenId         :: IO Identifier
  -- share part
  , solvTimeout       :: IO DNSMessage -> IO (Maybe DNSMessage)
  , solvGetTime       :: IO EpochTime
  , solvQueryControls :: QueryControls
  -- UDP only
  , solvRetry         :: Int
  }

defaultResolvInfo :: ResolvInfo
defaultResolvInfo = ResolvInfo {
    solvHostName      = "127.0.0.1"
  , solvPortNumber    = 53
  , solvGenId         = return 0
  , solvTimeout       = timeout 3000000
  , solvGetTime       = getEpochTime
  , solvQueryControls = mempty
  , solvRetry         = 3
  }

-- | The type of solvers (DNS over X).
type Resolver = Question -> ResolvInfo -> IO DNSMessage
