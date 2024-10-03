{-# LANGUAGE RecordWildCards #-}

-- | The server side of full resolver.
module DNS.Iterative.Server (
    -- * Types
    module DNS.Iterative.Query.Env,
    module DNS.Iterative.Server.Types,
    module DNS.RRCache,
    module DNS.TimeCache,

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
    RecvPI,
    Send,
    VcTimer (..),
    VcSession (..),
    VcFinished (..),
    VcPendings,
    withVcTimer,
    initVcSession,
    mkInput,
    noPendingOp,
    getRecvVC,
    receiverVC,
    getSendVC,
    senderVC,
    mkConnector,
    waitVcInput,
    waitVcOutput,
    enableVcEof,
    enableVcTimeout,
    addVcPending,
    delVcPending,
) where

import DNS.Iterative.Query.Env
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.HTTP3
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.PrometheusHisto (getHistogramBucktes)
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.TCP
import DNS.Iterative.Server.TLS
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP
import DNS.Iterative.Server.WorkerStats
import DNS.Iterative.Stats
import DNS.RRCache (RRCache, RRCacheConf (..), RRCacheOps (..), newRRCache, newRRCacheOps)
import qualified DNS.RRCache as RRCache
import DNS.TimeCache

import Control.Concurrent (getNumCapabilities)
import Data.ByteString.Builder
import Data.String (fromString)

getStats :: Env -> Builder -> IO Builder
getStats Env{..} prefix =
    mconcat <$> sequence [readStats stats_ prefix, getHistogramBucktes stats_ prefix, getGlobalStats]
  where
    getGlobalStats = (<>) <$> (cacheCount <$> getCache_) <*> (info <$> getNumCapabilities)
    cacheCount c = prefix <> fromString ("rrset_cache_count " <> show (RRCache.size c) <> "\n")
    info cap = prefix <> fromString ("info{threads=\"" ++ show cap ++ "\", version=\"0.0.0.20240801\"} 1\n")
