{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Resolver related data types.
module DNS.Do53.Types (
    -- * Configuration for resolver
    LookupConf (..),
    defaultLookupConf,
    UDPRetry,
    VCLimit (unVCLimit),
    LookupEnv (..),

    -- ** Specifying DNS servers
    Seeds (..),

    -- ** Configuring cache
    CacheConf (..),
    defaultCacheConf,

    -- * Type and function for resolver
    ResolvEnv (..),
    ResolvInfo (..),
    defaultResolvInfo,
    ResolvActions (..),
    defaultResolvActions,
    ResolvActionsFlag (RAFlagMultiLine),
    Result (..),
    Reply (..),
    Resolver,

    -- * IO
    Recv,
    RecvN,
    RecvMany,
    RecvManyN,
    Send,
    SendMany,
)
where

import DNS.Types
import DNS.Types.Decode
import Network.Socket (HostName, PortNumber, Socket)
#ifdef mingw32_HOST_OS
import Network.Socket (setSocketOption, SocketOption(..))
#endif
import DNS.Do53.Id
import DNS.Do53.Imports
import DNS.Do53.Query
import DNS.Log (PutLines)
import DNS.RRCache
import Prelude
import System.Timeout (timeout)

----------------------------------------------------------------

-- | The type to specify a cache server.
data Seeds
    = -- | A path for \"resolv.conf\"
      -- where one or more IP addresses
      -- of DNS servers should be found
      -- on Unix.
      -- Default DNS servers are
      -- automatically detected
      -- on Windows regardless of
      -- the value of the file name.
      SeedsFilePath FilePath
    | -- | A numeric IP address. /Warning/: host names are invalid.
      SeedsHostName HostName
    | -- | Numeric IP addresses. /Warning/: host names are invalid.
      SeedsHostNames [HostName]
    | -- | A numeric IP address and port number. /Warning/: host names are invalid.
      SeedsHostPort HostName PortNumber
    | SeedsHostPorts [(HostName, PortNumber)]
    deriving (Show)

----------------------------------------------------------------

-- | Cache configuration for responses.
data CacheConf = CacheConf
    { maximumTTL :: TTL
    -- ^ If RR's TTL is higher than this value, this value is used instead.
    , minimumTTL :: TTL
    -- ^ If RR's TTL is lower than this value, this value is used instead.
    , pruningDelay :: Int
    -- ^ Cache pruning interval in seconds.
    }
    deriving (Show)

-- | Default cache configuration.
--
-- >>> defaultCacheConf
-- CacheConf {maximumTTL = 300(5 mins), minimumTTL = 0(secs), pruningDelay = 10}
defaultCacheConf :: CacheConf
defaultCacheConf = CacheConf 300 0 10

----------------------------------------------------------------

newtype UDPRetry = UDPRetry Int deriving (Eq, Num, Show)

newtype VCLimit = VCLimit {unVCLimit :: Int} deriving (Eq, Ord, Num, Show)

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
data LookupConf = LookupConf
    { lconfSeeds :: Seeds
    -- ^ Server information.
    , lconfRetry :: UDPRetry
    -- ^ The number of UDP retries including the first try.
    , lconfLimit :: VCLimit
    -- ^ How many bytes are allowed to be received on a virtual circuit.
    , lconfConcurrent :: Bool
    -- ^ Concurrent queries if multiple DNS servers are specified.
    , lconfCacheConf :: Maybe CacheConf
    -- ^ Cache configuration.
    , lconfQueryControls :: QueryControls
    -- ^ Overrides for the default flags used for queries via resolvers that use
    -- this configuration.
    , lconfActions :: ResolvActions
    -- ^ Actions for resolvers.
    }

-- | Return a default 'LookupConf':
--
-- * 'lconfSeeds' is 'SeedsFilePath' \"\/etc\/resolv.conf\".
-- * 'lconfRetry' is 3.
-- * 'lconfConcurrent' is False.
-- * 'lconfCacheConf' is Nothing.
-- * 'lconfQueryControls' is an empty set of overrides.
defaultLookupConf :: LookupConf
defaultLookupConf =
    LookupConf
        { lconfSeeds = SeedsFilePath "/etc/resolv.conf"
        , lconfRetry = 3
        , lconfLimit = 32 * 1024
        , lconfConcurrent = False
        , lconfCacheConf = Nothing
        , lconfQueryControls = mempty
        , lconfActions = defaultResolvActions
        }

----------------------------------------------------------------

-- | Abstract data type of DNS Resolver.
--   This includes newly seeded identifier generators for all
--   specified DNS servers and a cache database.
data LookupEnv = LookupEnv
    { lenvCache :: Maybe (RRCache, CacheConf)
    , lenvQueryControls :: QueryControls
    , lenvConcurrent :: Bool
    , lenvResolvEnv :: ResolvEnv
    , lenvActions :: ResolvActions -- for cache lookup
    }

data ResolvEnv = ResolvEnv
    { renvResolver :: Resolver
    , renvConcurrent :: Bool
    , renvResolvInfos :: [ResolvInfo]
    }

----------------------------------------------------------------

-- | Information for resolvers.
data ResolvInfo = ResolvInfo
    { rinfoHostName :: HostName
    , rinfoPortNumber :: PortNumber
    , rinfoActions :: ResolvActions
    }

defaultResolvInfo :: ResolvInfo
defaultResolvInfo =
    ResolvInfo
        { rinfoHostName = "127.0.0.1"
        , rinfoPortNumber = 53
        , rinfoActions = defaultResolvActions
        }

data Result = Result
    { resultHostName :: HostName
    , resultPortNumber :: PortNumber
    , resultTag :: String
    , resultReply :: Reply
    }
    deriving (Eq, Show)

data Reply = Reply
    { replyDNSMessage :: DNSMessage
    , replyTxBytes :: Int
    , replyRxBytes :: Int
    }
    deriving (Eq, Show)

-- | The type of resolvers (DNS over X).
type Resolver = ResolvInfo -> Question -> QueryControls -> IO Result

----------------------------------------------------------------

newtype ResolvActionsFlag = ResolvActionsFlag Int deriving (Eq)

pattern RAFlagMultiLine :: ResolvActionsFlag
pattern RAFlagMultiLine = ResolvActionsFlag 1

data ResolvActions = ResolvActions
    { ractionTimeout :: IO Reply -> IO (Maybe Reply)
    , ractionGenId :: IO Identifier
    , ractionGetTime :: IO EpochTime
    , ractionSetSockOpt :: Socket -> IO ()
    , ractionLog :: PutLines
    , ractionFlags :: [ResolvActionsFlag]
    }

defaultResolvActions :: ResolvActions
defaultResolvActions =
    ResolvActions
        { ractionTimeout = timeout 3000000
        , ractionGenId = singleGenId
        , ractionGetTime = getEpochTime
        , ractionSetSockOpt = rsso
        , ractionLog = \_ _ ~_ -> return ()
        , ractionFlags = []
        }

rsso :: Socket -> IO ()
#ifdef mingw32_HOST_OS
rsso sock = setSocketOption sock RecvTimeOut 3000000
#else
rsso _ = return ()
#endif

----------------------------------------------------------------

type Recv = IO ByteString

type RecvN = Int -> IO ByteString

type RecvMany = IO (Int, [ByteString])

type RecvManyN = Int -> IO (Int, [ByteString])

type Send = ByteString -> IO ()

type SendMany = [ByteString] -> IO ()
