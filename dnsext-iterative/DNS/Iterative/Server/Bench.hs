{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_HADDOCK hide #-}

module DNS.Iterative.Server.Bench (
    benchServer,
    Request,
) where

-- GHC packages
import Control.Concurrent.STM
import Control.Monad (forever)
import Data.ByteString (ByteString)

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages
import Network.Socket
import qualified Network.UDP as UDP

-- this package
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.Pipeline

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
    reqQ <- newTQueueIO
    resQ <- newTQueueIO
    let pipelines_per_socket = bench_pipelines
    let pipelines = replicate pipelines_per_socket [forever $ atomically $ writeTQueue resQ =<< readTQueue reqQ]
    return (concat pipelines, atomically . writeTQueue reqQ, atomically (readTQueue resQ))
benchServer bench_pipelines env _ = do
    myDummy <- getSockAddr "127.1.1.1" "53"
    clntDummy <- UDP.ClientSockAddr <$> getSockAddr "127.2.1.1" "53" <*> pure []

    let pipelines_per_socket = bench_pipelines
        workers_per_pipeline = 8 {- only used initial setup, benchmark runs on cached state -}
    (workers, toCacher) <- mkPipeline env pipelines_per_socket workers_per_pipeline

    resQ <- newTQueueIO

    let toSender = atomically . writeTQueue resQ

        enqueueReq (bs, ()) = toCacher (Input bs myDummy (PeerInfoUDP clntDummy) UDP toSender)
        dequeueRes = (\(Output bs _) ->(bs, ())) <$> atomically (readTQueue resQ)
    return (workers, enqueueReq, dequeueRes)
  where
    getSockAddr host port = do
        as <- getAddrInfo (Just $ defaultHints{addrSocketType = Datagram}) (Just host) (Just port)
        case as of
            a : _ -> pure $ addrAddress a
            [] -> fail $ "benchServer: fail to get addr for " ++ host ++ ":" ++ port
