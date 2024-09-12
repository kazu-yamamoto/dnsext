{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_HADDOCK hide #-}

module DNS.Iterative.Server.Bench (
    benchServer,
    Request,
) where

-- GHC packages
import Control.Concurrent
import Control.Monad (forever)
import Data.ByteString (ByteString)
import qualified Data.List.NonEmpty as NE

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages
import Network.Socket

-- this package
import DNS.Iterative.Internal
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

----------------------------------------------------------------
----------------------------------------------------------------
-- Benchmark

type Request a = (ByteString, a)
type Response a = (ByteString, a)

benchServer
    :: Int
    -> Env
    -> Bool
    -> IO ([IO ()], Request () -> IO (), IO (Response ()))
benchServer bench_pipelines _ True = do
    reqQ <- newChan
    resQ <- newChan
    let pipelines_per_socket = bench_pipelines
    let pipelines = replicate pipelines_per_socket [forever $ writeChan resQ =<< readChan reqQ]
    return (concat pipelines, writeChan reqQ, readChan resQ)
benchServer bench_pipelines env _ = do
    myDummy <- getSockAddr "127.1.1.1" "53"
    clntDummy <- getSockAddr "127.2.1.1" "53"
    usecDummy <- currentTimeUsec_ env

    let pipelines_per_socket = bench_pipelines
        workers_per_pipeline = 8 {- only used initial setup, benchmark runs on cached state -}
    workerStats <- getWorkerStats workers_per_pipeline
    (cachers, workers, toCacher) <- mkPipeline env pipelines_per_socket workers_per_pipeline workerStats

    resQ <- newChan

    let toSender = writeChan resQ

        enqueueReq (bs, ()) = toCacher (Input bs noPendingOp myDummy (PeerInfoUDP clntDummy []) UDP toSender usecDummy)
        dequeueRes = (\(Output bs _ _) -> (bs, ())) <$> readChan resQ
    return (cachers ++ workers, enqueueReq, dequeueRes)
  where
    getSockAddr host port =
        addrAddress . NE.head
            <$> getAddrInfo (Just $ defaultHints{addrSocketType = Datagram, addrFlags = [AI_ADDRCONFIG]}) (Just host) (Just port)
