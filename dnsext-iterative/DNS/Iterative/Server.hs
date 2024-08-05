{-# LANGUAGE RecordWildCards #-}

-- | The server side of full resolver.
module DNS.Iterative.Server (
    -- * Types
    module DNS.Iterative.Query.Env,
    module DNS.Iterative.Server.Types,
    RRCacheOps (..),
    newRRCacheOps,
    TimeCache (..),
    newTimeCache,

    -- * Pipeline
    mkPipeline,
    getWorkerStats,

    -- * UDP
    UdpServerConfig (..),
    udpServers,

    -- * Virtual circuit
    VcServerConfig (..),
    http2Servers,
    http2cServers,
    http3Servers,
    quicServers,
    tcpServers,
    tlsServers,

    -- * WorkerStat
    WorkerStat (..),
    WorkerStatOP (..),
    pprWorkerStats,
    pprWorkerStat,

    -- * Stats
    getStats,

    -- * Tests
    Recv,
    Send,
    VcSession (..),
    VcFinished (..),
    VcPendings,
    initVcSession,
    mkInput,
    receiverVC,
    senderVC,
    mkConnector,
    waitVcInput,
    waitVcOutput,
    enableVcEof,
    addVcPending,
    delVcPending,
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
    info cap = prefix <> fromString ("info{threads=\"" ++ show cap ++ "\", version=\"0.0.0.20240801\"} 1\n")
