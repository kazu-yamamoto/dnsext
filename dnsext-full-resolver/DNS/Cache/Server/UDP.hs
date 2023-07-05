{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.UDP where

-- GHC packages
import Control.Monad (forever, replicateM)
import Data.ByteString (ByteString)
import Data.IORef (atomicModifyIORef', newIORef, readIORef)

-- dnsext-* packages
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import Data.IP (IP (..))
import Network.Socket (
    PortNumber,
 )
import qualified Network.UDP as UDP

-- other packages
import UnliftIO (SomeException, handle)

-- this package
import DNS.Cache.Iterative (CacheResult (..), Env (..), getResponseCached, getResponseIterative)
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
import qualified DNS.Log as Log

----------------------------------------------------------------

data UdpServerConfig = UdpServerConfig
    { udp_pipelines_per_socket :: Int
    , udp_workers_per_pipline :: Int
    , udp_queue_size_per_worker :: Int
    , udp_worker_share_queue :: Bool
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
    -> IO ([IO ()], PLStatus)
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
    -> IO ([IO ([IO ()], WorkerStatus)], Request a -> IO (), IO (Response a))
getPipelines udpconf@UdpServerConfig{..} env
    | udp_queue_size_per_worker <= 0 = do
        reqQ <- newQueueChan
        resQ <- newQueueChan
        {- share request queue and response queue -}
        let udpconf' = udpconf { udp_queue_size_per_worker = 8 }
            wps = replicate udp_pipelines_per_socket $ getCacherWorkers reqQ resQ udpconf' env
        return (wps, writeQueue reqQ, readQueue resQ)
    | udp_worker_share_queue = do
        let qsize = udp_queue_size_per_worker * udp_pipelines_per_socket
        reqQ <- newQueue qsize
        resQ <- newQueue qsize
        {- share request queue and response queue -}
        let wps = replicate udp_pipelines_per_socket $ getCacherWorkers reqQ resQ udpconf env
        return (wps, writeQueue reqQ, readQueue resQ)
    | otherwise = do
        reqQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_worker
        enqueueReq <- Queue.writeQueue <$> Queue.makePutAny reqQs
        resQs <- replicateM udp_pipelines_per_socket $ newQueue udp_queue_size_per_worker
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
    -> IO ([IO ()], WorkerStatus)
getCacherWorkers reqQ resQ UdpServerConfig{..} env = do
    (CntGet{..}, incs) <- newCounters

    let logr = putLn Log.WARN . ("Server.worker: error: " ++) . show
        worker = getWorker env incs enqueueResp
    (resolvLoop, enqueueDec, decQSize) <- consumeLoop udp_queue_size_per_worker logr worker

    let logc = putLn Log.WARN . ("Server.cacher: error: " ++) . show
        cacher = getCacher env incs enqueueDec enqueueResp
        cachedLoop = handledLoop logc (readQueue reqQ >>= cacher)

        resolvLoops = replicate udp_workers_per_pipline resolvLoop
        loops = resolvLoops ++ [cachedLoop]

        workerStatus = WorkerStatus reqQSize decQSize resQSize getHit' getMiss' getFailed'

    return (loops, workerStatus)
  where
    putLn lv = logLines_ env lv Nothing . (: [])
    enqueueResp = writeQueue resQ
    resQSize = queueSize resQ
    reqQSize = queueSize reqQ

----------------------------------------------------------------

getCacher
    :: Show a
    => Env
    -> CntInc
    -> EnqueueDec a
    -> EnqueueResp a
    -> Request a
    -> IO ()
getCacher env CntInc{..} enqueueDec enqueueResp (bs, addr) = do
    now <- currentSeconds_ env
    case DNS.decodeAt now bs of
        Left e -> logLn Log.WARN $ "decode-error: " ++ show e
        Right reqM -> do
            mx <- getResponseCached env reqM
            case mx of
                None ->
                    enqueueDec (reqM, addr)
                Positive respM -> do
                    incHit
                    let rbs = DNS.encode respM
                    rbs `seq` enqueueResp (rbs, addr)
                Negative replyErr -> do
                    incFailed
                    logLn Log.WARN $
                        "cached: response cannot be generated: "
                            ++ replyErr
                            ++ ": "
                            ++ show (DNS.question reqM, addr)
  where
    logLn level = logLines_ env level Nothing . (: [])

----------------------------------------------------------------

getWorker
    :: Show a
    => Env
    -> CntInc
    -> EnqueueResp a
    -> Decoded a
    -> IO ()
getWorker env CntInc{..} enqueueResp (reqM, addr) = do
    ex <- getResponseIterative env reqM
    case ex of
        Right x -> do
            incMiss
            let rbs = DNS.encode x
            rbs `seq` enqueueResp (rbs, addr)
        Left e -> do
            incFailed
            logLn Log.WARN $
                "resolv: response cannot be generated: "
                    ++ e
                    ++ ": "
                    ++ show (DNS.question reqM, addr)
  where
    logLn level = logLines_ env level Nothing . (: [])

----------------------------------------------------------------

consumeLoop
    :: Int
    -> (SomeException -> IO ())
    -> (Decoded a -> IO ())
    -> IO (IO (), EnqueueDec a, IO (Int, Int))
consumeLoop qsize onError body = do
    inQ <- newQueue qsize
    let loop = handledLoop onError (readQueue inQ >>= body)
    return (loop, writeQueue inQ, queueSize inQ)

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

data WorkerStatus = WorkerStatus
    { reqQSize :: IO (Int, Int)
    , decQSize :: IO (Int, Int)
    , resQSize :: IO (Int, Int)
    , getHit :: IO Int
    , getMiss :: IO Int
    , getFailed :: IO Int
    }

type PLStatus = [WorkerStatus]

data CntGet = CntGet
    { getHit' :: IO Int
    , getMiss' :: IO Int
    , getFailed' :: IO Int
    }

data CntInc = CntInc
    { incHit :: IO ()
    , incMiss :: IO ()
    , incFailed :: IO ()
    }

newCounters :: IO (CntGet, CntInc)
newCounters = do
    (g0, i0) <- counter
    (g1, i1) <- counter
    (g2, i2) <- counter
    return (CntGet g0 g1 g2, CntInc i0 i1 i2)
  where
    counter :: IO (IO Int, IO ())
    counter = do
        ref <- newIORef 0
        return (readIORef ref, atomicModifyIORef' ref (\x -> (x + 1, ())))
