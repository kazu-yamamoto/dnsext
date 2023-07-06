{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.UDP where

-- GHC packages
import Control.Monad (forever, replicateM)
import Data.ByteString (ByteString)

-- dnsext-* packages
import qualified DNS.Types as DNS
import Data.IP (IP (..))
import Network.Socket (
    PortNumber,
 )
import qualified Network.UDP as UDP

-- other packages
import qualified DNS.Log as Log
import UnliftIO (SomeException, handle)

-- this package
import DNS.Cache.Iterative (Env (..))
import DNS.Cache.Queue (
    QueueSize,
    ReadQueue,
    WriteQueue,
    newQueue,
    newQueueChan,
    readQueue,
    writeQueue,
 )
import qualified DNS.Cache.Queue as Queue
import DNS.Cache.Server.Pipeline

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

udpServer
    :: UdpServerConfig
    -> Env
    -> PortNumber
    -> IP
    -> IO ([IO ()], [IO Status])
udpServer conf env port hostIP = do
    sock <- UDP.serverSocket (hostIP, port)
    let putLn lv = logLines_ env lv Nothing . (: [])

    (mkPipelines, enqueueReq, dequeueResp) <- getPipelines conf env
    (pipelines, getsStatus) <- unzip <$> sequence mkPipelines

    let onErrorR = putLn Log.WARN . ("Server.recvRequest: error: " ++) . show
        receiver = handledLoop onErrorR (UDP.recvFrom sock >>= enqueueReq)

    let onErrorS = putLn Log.WARN . ("Server.sendResponse: error: " ++) . show
        sender = handledLoop onErrorS (dequeueResp >>= uncurry (UDP.sendTo sock))
    return (receiver : sender : concat pipelines, getsStatus)

----------------------------------------------------------------

getPipelines
    :: Show a
    => UdpServerConfig
    -> Env
    -> IO ([IO ([IO ()], IO Status)], Request a -> IO (), IO (Response a))
getPipelines udpconf@UdpServerConfig{..} env
    | udp_queue_size_per_pipeline <= 0 = do
        reqQ <- newQueueChan
        resQ <- newQueueChan
        {- share request queue and response queue -}
        let udpconf' = udpconf{udp_queue_size_per_pipeline = 8}
            wps = replicate udp_pipelines_per_socket $ getCacherWorkers reqQ resQ udpconf' env
        return (wps, writeQueue reqQ, readQueue resQ)
    | udp_pipeline_share_queue = do
        let qsize = udp_queue_size_per_pipeline * udp_pipelines_per_socket
        reqQ <- newQueue qsize
        resQ <- newQueue qsize
        {- share request queue and response queue -}
        let wps = replicate udp_pipelines_per_socket $ getCacherWorkers reqQ resQ udpconf env
        return (wps, writeQueue reqQ, readQueue resQ)
    | otherwise = do
        reqQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_pipeline
        enqueueReq <- Queue.writeQueue <$> Queue.makePutAny reqQs
        resQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_pipeline
        dequeueResp <- Queue.readQueue <$> Queue.makeGetAny resQs
        let wps =
                [ getCacherWorkers reqQ resQ udpconf env
                | reqQ <- reqQs
                | resQ <- resQs
                ]
        return (wps, enqueueReq, dequeueResp)

----------------------------------------------------------------

getCacherWorkers
    :: (Show a, ReadQueue rq, QueueSize rq, WriteQueue wq, QueueSize wq)
    => rq (Request a)
    -> wq (Response a)
    -> UdpServerConfig
    -> Env
    -> IO ([IO ()], IO Status)
getCacherWorkers reqQ resQ UdpServerConfig{..} env = do
    (CntGet{..}, incs) <- newCounters

    let logr = putLn Log.WARN . ("Server.worker: error: " ++) . show
    (resolvLoop, enqueueDec, decQSize) <- do
        inQ <- newQueue udp_queue_size_per_pipeline
        let loop = handledLoop logr $ do
                (reqMsg, addr) <- readQueue inQ
                let enqueueResp' x = enqueueResp (x, addr)
                workerLogic env incs enqueueResp' reqMsg
        return (loop, writeQueue inQ, queueSize inQ)

    let logc = putLn Log.WARN . ("Server.cacher: error: " ++) . show
        cachedLoop = handledLoop logc $ do
            (req, addr) <- readQueue reqQ
            let enqueueDec' x = enqueueDec (x, addr)
                enqueueResp' x = enqueueResp (x, addr)
            cacherLogic env incs enqueueResp' enqueueDec' req

        resolvLoops = replicate udp_workers_per_pipeline resolvLoop
        loops = resolvLoops ++ [cachedLoop]

        status = getStatus reqQSize decQSize resQSize getHit' getMiss' getFailed'

    return (loops, status)
  where
    putLn lv = logLines_ env lv Nothing . (: [])
    enqueueResp = writeQueue resQ
    resQSize = queueSize resQ
    reqQSize = queueSize reqQ

----------------------------------------------------------------

handledLoop :: (SomeException -> IO ()) -> IO () -> IO ()
handledLoop onError body = forever $ handle onError body

----------------------------------------------------------------

queueSize :: QueueSize q => q a -> IO (Int, Int)
queueSize q = do
    a <- fst <$> Queue.readSizes q
    let b = Queue.sizeMaxBound q
    return (a, b)

----------------------------------------------------------------

getStatus :: IO (Int, Int) -> IO (Int, Int) -> IO (Int, Int) -> IO Int -> IO Int -> IO Int -> IO [(String, Int)]
getStatus reqQSize decQSize resQSize getHit getMiss getFailed = do
    (nreq, mreq) <- reqQSize
    (ndec, mdec) <- decQSize
    (nres, mres) <- resQSize
    hit <- getHit
    miss <- getMiss
    fail_ <- getFailed
    return
        [ ("request queue size", nreq)
        , ("decoded queue size", ndec)
        , ("response queue size", nres)
        , ("request queue max size", mreq)
        , ("decoded queue max size", mdec)
        , ("response queue max size", mres)
        , ("hit", hit)
        , ("miss", miss)
        , ("fail", fail_)
        ]
