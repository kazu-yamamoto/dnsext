{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.UDP where

-- GHC packages
import Control.Monad (forever, replicateM)
import Data.ByteString (ByteString)

-- dnsext-* packages
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS

-- other packages
import qualified DNS.Log as Log
import Network.Socket (SockAddr)
import qualified Network.UDP as UDP
import UnliftIO (SomeException, handle)

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Queue (
    QueueSize,
    ReadQueue,
    WriteQueue,
    newQueue,
    newQueueChan,
    readQueue,
    writeQueue,
 )
import qualified DNS.Iterative.Queue as Queue
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.TAP.Schema (SocketProtocol (..))

----------------------------------------------------------------

data UdpServerConfig = UdpServerConfig
    { udp_pipelines_per_socket :: Int
    , udp_workers_per_pipeline :: Int
    , udp_queue_size_per_pipeline :: Int
    , udp_pipeline_share_queue :: Bool
    }

type Request a = (ByteString, a)
type Decoded a = (DNS.DNSMessage, a)
type Response a = (ByteString, a)

type EnqueueDec a = Decoded a -> IO ()
type EnqueueResp a = Response a -> IO ()

----------------------------------------------------------------

----------------------------------------------------------------

--                          <---------  Pipeline  -------------->
--
--                                       Iterative IO
--                                         Req Resp
--                            cache         ^   |
--                              |           |   v
--        +--------+ shared +--------+    +--------+    +--------+
-- Req -> | recver | -----> | cacher | -> | worker | -> | sender | -> Resp
--        +--------+ or any +--------|    +--------+    +--------+
--                               |                          ^
--                               +--------------------------+
--                                        Cache hit
--

----------------------------------------------------------------

udpServer :: UdpServerConfig -> Server
udpServer conf env port addr = do
    lsock <- UDP.serverSocket (read addr, port)
    let mysa = UDP.mySockAddr lsock
        putLn lv = logLines_ env lv Nothing . (: [])

    (mkPipelines, enqueueReq, dequeueResp) <- getPipelines conf env mysa
    pipelines <- sequence mkPipelines

    let onErrorR = putLn Log.WARN . ("Server.recvRequest: error: " ++) . show
        receiver = handledLoop onErrorR (UDP.recvFrom lsock >>= enqueueReq)

    let onErrorS = putLn Log.WARN . ("Server.sendResponse: error: " ++) . show
        sender = handledLoop onErrorS (dequeueResp >>= uncurry (UDP.sendTo lsock))
    return (receiver : sender : concat pipelines)

----------------------------------------------------------------

getPipelines
    :: UdpServerConfig
    -> Env
    -> SockAddr
    -> IO ([IO [IO ()]], Request UDP.ClientSockAddr -> IO (), IO (Response UDP.ClientSockAddr))
getPipelines udpconf@UdpServerConfig{..} env mysa
    | udp_queue_size_per_pipeline <= 0 = do
        reqQ <- newQueueChan
        resQ <- newQueueChan
        {- share request queue and response queue -}
        let udpconf' = udpconf{udp_queue_size_per_pipeline = 8}
            wps = replicate udp_pipelines_per_socket $ getCacherWorkers reqQ resQ udpconf' env mysa
        return (wps, writeQueue reqQ, readQueue resQ)
    | udp_pipeline_share_queue = do
        let qsize = udp_queue_size_per_pipeline * udp_pipelines_per_socket
        reqQ <- newQueue qsize
        resQ <- newQueue qsize
        {- share request queue and response queue -}
        let wps = replicate udp_pipelines_per_socket $ getCacherWorkers reqQ resQ udpconf env mysa
        return (wps, writeQueue reqQ, readQueue resQ)
    | otherwise = do
        reqQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_pipeline
        enqueueReq <- Queue.writeQueue <$> Queue.makePutAny reqQs
        resQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_pipeline
        dequeueResp <- Queue.readQueue <$> Queue.makeGetAny resQs
        let wps =
                [ getCacherWorkers reqQ resQ udpconf env mysa
                | reqQ <- reqQs
                | resQ <- resQs
                ]
        return (wps, enqueueReq, dequeueResp)

----------------------------------------------------------------

getCacherWorkers
    :: (ReadQueue rq, QueueSize rq, WriteQueue wq, QueueSize wq)
    => rq (Request UDP.ClientSockAddr)
    -> wq (Response UDP.ClientSockAddr)
    -> UdpServerConfig
    -> Env
    -> SockAddr
    -> IO ([IO ()])
getCacherWorkers reqQ resQ UdpServerConfig{..} env mysa = do
    let logr = putLn Log.WARN . ("Server.worker: error: " ++) . show
    (resolvLoop, enqueueDec, _decQSize) <- do
        inQ <- newQueue udp_queue_size_per_pipeline
        let loop = handledLoop logr $ do
                (reqMsg, clisa@(UDP.ClientSockAddr peersa _)) <- readQueue inQ
                let enqueueResp' x = enqueueResp (x, clisa)
                workerLogic env enqueueResp' UDP mysa peersa reqMsg
        return (loop, writeQueue inQ, queueSize inQ)

    let logc = putLn Log.WARN . ("Server.cacher: error: " ++) . show
        cachedLoop = handledLoop logc $ do
            (req, clisa@(UDP.ClientSockAddr peersa _)) <- readQueue reqQ
            let enqueueDec' x = enqueueDec (x, clisa)
                enqueueResp' x = enqueueResp (x, clisa)
            cacherLogic env enqueueResp' DNS.decodeAt enqueueDec' UDP mysa peersa req

        resolvLoops = replicate udp_workers_per_pipeline resolvLoop
        loops = resolvLoops ++ [cachedLoop]

    return loops
  where
    putLn lv = logLines_ env lv Nothing . (: [])
    enqueueResp = writeQueue resQ

----------------------------------------------------------------

handledLoop :: (SomeException -> IO ()) -> IO () -> IO ()
handledLoop onError body = forever $ handle onError body

----------------------------------------------------------------

queueSize :: QueueSize q => q a -> IO (Int, Int)
queueSize q = do
    a <- fst <$> Queue.readSizes q
    let b = Queue.sizeMaxBound q
    return (a, b)
