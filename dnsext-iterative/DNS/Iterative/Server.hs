{-# LANGUAGE RecordWildCards #-}

-- | The server side of full resolver.
module DNS.Iterative.Server (
    -- * Types
    Server,
    HostName,
    PortNumber,
    module DNS.Iterative.Query.Env,
    RRCacheOps (..),
    newRRCacheOps,
    TimeCache (..),
    newTimeCache,

    -- * Pipeline
    mkPipeline,
    getWorkerStats,
    ToCacher,
    Input,

    -- * UDP
    UdpServerConfig (..),
    udpServer,

    -- * Virtual circuit
    VcServerConfig (..),
    tcpServer,
    http2Server,
    http2cServer,
    http3Server,
    tlsServer,
    quicServer,

    -- * Errors
    withLocationIOE,

    -- * WorkerStat
    WorkerStat (..),
    WorkerStatOP (..),
    pprWorkerStats,
    pprWorkerStat,

    -- * Stats
    getStats,
) where

import DNS.Iterative.Query.Env
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.HTTP3
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.TCP
import DNS.Iterative.Server.TLS
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP
import DNS.Iterative.Server.WorkerStats
import DNS.Iterative.Stats
import DNS.RRCache (RRCacheOps (..), newRRCacheOps)
import qualified DNS.RRCache as RRCache
import DNS.TimeCache (TimeCache (..), newTimeCache)

import Control.Concurrent (getNumCapabilities)
import Data.ByteString.Builder
import Data.String (fromString)

getStats :: Env -> Builder -> IO Builder
getStats Env{..} prefix =
    (<>) <$> readStats stats_ prefix <*> getGlobalStats
  where
    getGlobalStats = (<>) <$> (cacheCount <$> getCache_) <*> (info <$> getNumCapabilities)
    cacheCount c = prefix <> fromString ("rrset_cache_count " <> show (RRCache.size c) <> "\n")
    info cap = prefix <> fromString ("info{threads=\"" ++ show cap ++ "\", version=\"0.0.0.20240605\"} 1\n")
