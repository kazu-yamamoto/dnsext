{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.Bench (
    benchServer,
    UdpServerConfig (..),
    Request,
) where

-- GHC packages
import Control.Monad (forever)

-- dnsext-* packages

-- other packages

-- this package
import DNS.Cache.Queue (
    newQueue,
    readQueue,
    writeQueue,
 )
import DNS.Cache.Server.Types
import DNS.Cache.Server.UDP

----------------------------------------------------------------
----------------------------------------------------------------
-- Benchmark

benchServer
    :: UdpServerConfig
    -> Env
    -> Bool
    -> IO ([[IO ()]], Request () -> IO (), IO (Request ()))
benchServer UdpServerConfig{..} _ True = do
    let qsize = udp_queue_size_per_pipeline * udp_pipelines_per_socket
    reqQ <- newQueue qsize
    resQ <- newQueue qsize
    let pipelines = replicate udp_pipelines_per_socket [forever $ writeQueue resQ =<< readQueue reqQ]
    return (pipelines, writeQueue reqQ, readQueue resQ)
benchServer udpconf env _ = do
    (workerPipelines, enqueueReq, dequeueRes) <- undefined
    {-
        getPipelines udpconf env undefined
            :: IO ([IO ([IO ()], IO Status)], Request () -> IO (), IO (Response ()))
-}
    (workers, _getsStatus) <- unzip <$> sequence workerPipelines
    return (workers, enqueueReq, dequeueRes)
