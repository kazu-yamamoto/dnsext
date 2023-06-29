{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server (
    Config (..),
    run,
    runBenchmark,
) where

-- GHC packages
import Control.Concurrent (forkIO, getNumCapabilities)
import Control.DeepSeq (deepseq)
import Control.Monad (forever, replicateM)
import Data.ByteString (ByteString)
import Data.IORef (atomicModifyIORef', newIORef, readIORef)
import Data.Maybe (mapMaybe)
import Data.String (fromString)
import Data.Time (NominalDiffTime, diffUTCTime, getCurrentTime)

-- dnsext-* packages

import qualified DNS.Do53.Memo as Cache
import qualified DNS.SEC as DNS
import qualified DNS.Types as DNS
import DNS.Types.Decode (EpochTime)
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import Data.IP (IP (..), fromHostAddress, fromHostAddress6)
import Network.Socket (
    AddrInfo (..),
    HostName,
    PortNumber,
    SockAddr (..),
    SocketType (Datagram),
    getAddrInfo,
 )
import qualified Network.UDP as UDP

-- other packages
import UnliftIO (SomeException, concurrently_, handle, race_)

-- this package

import DNS.Cache.Iterative (CacheResult (..), Env (..), getReplyCached, getReplyMessage)
import qualified DNS.Cache.Iterative as Iterative
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
import DNS.Cache.ServerMonitor (PLStatus, WorkerStatus (WorkerStatus), monitor)
import qualified DNS.Cache.ServerMonitor as Mon
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Log as Log

----------------------------------------------------------------

data Config = Config
    { logOutput :: Log.Output
    , logLevel :: Log.Level
    , maxCacheSize :: Int
    , disableV6NS :: Bool
    , nOfPipelines :: Int
    , qsizePerWorker :: Int
    , workerSharedQueue :: Bool
    }

type Request a = (ByteString, a)
type Decoded a = (DNS.DNSMessage, a)
type Response a = (ByteString, a)

type EnqueueDec a = Decoded a -> IO ()
type EnqueueResp a = Response a -> IO ()

----------------------------------------------------------------

run
    :: Config
    -> PortNumber
    -> [HostName]
    -> Bool
    -- ^ standard console or not
    -> IO ()
run conf port hosts stdConsole = do
    DNS.runInitIO DNS.addResourceDataForDNSSEC
    (serverLoops, monLoops) <- setup conf port hosts stdConsole
    race_
        (foldr concurrently_ (return ()) serverLoops)
        (foldr concurrently_ (return ()) monLoops)

----------------------------------------------------------------

setup
    :: Config
    -> PortNumber
    -> [HostName]
    -> Bool
    -> IO ([IO ()], [IO ()])
setup conf@Config{..} port hosts stdConsole = do
    (putLines, logQSize, terminate) <- Log.new logOutput logLevel
    (env, getSec, expires) <- getEnv conf putLines
    hostIPs <- getHostIPs hosts port

    let getP = getPipeline conf getSec env port
    (loopsList, qsizes) <- unzip <$> mapM getP hostIPs
    let pLoops = concat loopsList

    caps <- getNumCapabilities
    let params = mkParams caps

    putLines Log.WARN Nothing $ map ("params: " ++) $ Mon.showParams params

    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
    monLoops <-
        monitor stdConsole params env (qsizes, ucacheQSize, logQSize) expires terminate

    return (pLoops, monLoops)
  where
    getHostIPs [] p = getAInfoIPs p
    getHostIPs hs _ = return $ map fromString hs
    mkParams caps =
        Mon.makeParams
            caps
            logOutput
            logLevel
            maxCacheSize
            disableV6NS
            nOfPipelines
            workerSharedQueue
            qsizePerWorker
            port
            hosts

----------------------------------------------------------------

getEnv
    :: Config -> Log.PutLines -> IO (Env, IO EpochTime, EpochTime -> IO ())
getEnv Config{..} putLines = do
    tcache@(getSec, getTimeStr) <- TimeCache.new
    let cacheConf = Cache.MemoConf maxCacheSize 1800 memoActions
          where
            memoLogLn msg = do
                tstr <- getTimeStr
                putLines Log.WARN Nothing [tstr $ ": " ++ msg]
            memoActions = Cache.MemoActions memoLogLn getSec
    memo <- Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
        expires now = Cache.expiresMemo now memo
        read' = Cache.readMemo memo
    env <- Iterative.newEnv putLines disableV6NS (insert, read') tcache
    return (env, getSec, expires)

----------------------------------------------------------------

getAInfoIPs :: PortNumber -> IO [IP]
getAInfoIPs port = do
    ais <- getAddrInfo Nothing Nothing (Just $ show port)
    let dgramIP AddrInfo{addrAddress = SockAddrInet _ ha} = Just $ IPv4 $ fromHostAddress ha
        dgramIP AddrInfo{addrAddress = SockAddrInet6 _ _ ha6 _} = Just $ IPv6 $ fromHostAddress6 ha6
        dgramIP _ = Nothing
    return $
        mapMaybe dgramIP [ai | ai@AddrInfo{addrSocketType = Datagram} <- ais]

----------------------------------------------------------------

-- Pipeline
--
--                                  Iterative IO
--                                     Req Resp
--                         Cache        ^   |
--                           |          |   v
--        +--------+    +--------+    +--------+    +--------+
-- Req -> | recver | -> | cacher | -> | worker | -> | sender | -> Resp
--        +--------+    +--------|    +--------+    +--------+
--                           |                          ^
--                           +--------------------------+
--                                    Cache hit
--

----------------------------------------------------------------

getPipeline
    :: Config
    -> IO EpochTime
    -> Env
    -> PortNumber
    -> IP
    -> IO ([IO ()], PLStatus)
getPipeline conf getSec env port hostIP = do
    sock <- UDP.serverSocket (hostIP, port)
    let putLn lv = logLines_ env lv Nothing . (: [])

    (workerPipelines, enqueueReq, dequeueResp) <-
        getWorkers conf getSec env
    (workers, getsStatus) <- unzip <$> sequence workerPipelines

    let onErrorR = putLn Log.WARN . ("Server.recvRequest: error: " ++) . show
        receiver = handledLoop onErrorR (UDP.recvFrom sock >>= enqueueReq)

    let onErrorS = putLn Log.WARN . ("Server.sendResponse: error: " ++) . show
        sender = handledLoop onErrorS (dequeueResp >>= uncurry (UDP.sendTo sock))
    return (receiver : sender : concat workers, getsStatus)

----------------------------------------------------------------

getWorkers
    :: Show a
    => Config
    -> IO EpochTime
    -> Env
    -> IO ([IO ([IO ()], WorkerStatus)], Request a -> IO (), IO (Response a))
getWorkers Config{..} getSec env
    | qsizePerWorker <= 0 = do
        reqQ <- newQueueChan
        resQ <- newQueueChan
        {- share request queue and response queue -}
        let wps = replicate nOfPipelines $ getSenderReceiver reqQ resQ 8 getSec env
        return (wps, writeQueue reqQ, readQueue resQ)
    | workerSharedQueue = do
        let qsize = qsizePerWorker * nOfPipelines
        reqQ <- newQueue qsize
        resQ <- newQueue qsize
        {- share request queue and response queue -}
        let wps =
                replicate nOfPipelines $ getSenderReceiver reqQ resQ qsizePerWorker getSec env
        return (wps, writeQueue reqQ, readQueue resQ)
    | otherwise = do
        reqQs <- replicateM nOfPipelines $ newQueue qsizePerWorker
        enqueueReq <- Queue.writeQueue <$> Queue.makePutAny reqQs
        resQs <- replicateM nOfPipelines $ newQueue qsizePerWorker
        dequeueResp <- Queue.readQueue <$> Queue.makeGetAny resQs
        let wps =
                [ getSenderReceiver reqQ resQ qsizePerWorker getSec env
                | reqQ <- reqQs
                | resQ <- resQs
                ]
        return (wps, enqueueReq, dequeueResp)

----------------------------------------------------------------

getSenderReceiver
    :: (Show a, ReadQueue rq, QueueSize rq, WriteQueue wq, QueueSize wq)
    => rq (Request a)
    -> wq (Response a)
    -> Int
    -> IO EpochTime
    -> Env
    -> IO ([IO ()], WorkerStatus)
getSenderReceiver reqQ resQ qsizePerWorker getSec env = do
    (CntGet{..}, incs) <- newCounters

    let logr = putLn Log.WARN . ("Server.worker: error: " ++) . show
        worker = getWorker env incs enqueueResp
    (resolvLoop, enqueueDec, decQSize) <- consumeLoop qsizePerWorker logr worker

    let logc = putLn Log.WARN . ("Server.cacher: error: " ++) . show
        cacher = getCacher env getSec incs enqueueDec enqueueResp
        cachedLoop = handledLoop logc (readQueue reqQ >>= cacher)

        resolvLoops = replicate nOfResolvWorkers resolvLoop
        loops = resolvLoops ++ [cachedLoop]

        workerStatus = WorkerStatus reqQSize decQSize resQSize getHit getMiss getFailed

    return (loops, workerStatus)
  where
    nOfResolvWorkers = 8
    putLn lv = logLines_ env lv Nothing . (: [])
    enqueueResp = writeQueue resQ
    resQSize = queueSize resQ
    reqQSize = queueSize reqQ

----------------------------------------------------------------

getCacher
    :: Show a
    => Env
    -> IO EpochTime
    -> CntInc
    -> EnqueueDec a
    -> EnqueueResp a
    -> Request a
    -> IO ()
getCacher env getSec CntInc{..} enqueueDec enqueueResp (bs, addr) = do
    now <- getSec
    case DNS.decodeAt now bs of
        Left e -> logLn Log.WARN $ "decode-error: " ++ show e
        Right reqM -> do
            mx <- getReplyCached env reqM
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
    ex <- getReplyMessage env reqM
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

data CntGet = CntGet
    { getHit :: IO Int
    , getMiss :: IO Int
    , getFailed :: IO Int
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

----------------------------------------------------------------
----------------------------------------------------------------
-- Benchmark

benchQueries :: [ByteString]
benchQueries =
    [ DNS.encode $ setId mid rootA {- TODO: seq ByteString ? -}
    | mid <- cycle [0 .. maxBound]
    | rootA <- cycle rootAs
    ]
  where
    setId mid qm = qm{DNS.header = dh{DNS.identifier = mid}}
    dh = DNS.header DNS.defaultQuery
    rootAs =
        [ DNS.defaultQuery
            { DNS.question = [DNS.Question (fromString name) DNS.A DNS.classIN]
            }
        | c1 <- ["a", "b", "c", "d"]
        , let name = c1 ++ ".root-servers.net."
        ]

----------------------------------------------------------------

runBenchmark
    :: Config
    -> Bool
    -- ^ No operation or not
    -> Bool
    -- ^ Gnuplot mode or not
    -> Int
    -- ^ Request size
    -> IO ()
runBenchmark conf@Config{..} noop gplot size = do
    (putLines, _logQSize, _terminate) <- Log.new logOutput logLevel
    (env, getSec) <- getEnvB conf putLines

    (workers, enqueueReq, dequeueResp) <-
        getPipelineB noop conf env getSec
    _ <- forkIO $ foldr concurrently_ (return ()) $ concat workers

    let (initD, ds) = splitAt 4 $ take (4 + size) benchQueries
    ds `deepseq` return ()

    -----
    _ <- runQueriesB initD enqueueReq dequeueResp
    before <- getCurrentTime
    _ <- runQueriesB ds enqueueReq dequeueResp
    after <- getCurrentTime

    let elapsed = after `diffUTCTime` before
        toDouble = fromRational . toRational :: NominalDiffTime -> Double
        rate = toDouble $ fromIntegral size / after `diffUTCTime` before

    if gplot
        then do
            putStrLn $ unwords [show nOfPipelines, show rate]
        else do
            putStrLn . ("capabilities: " ++) . show =<< getNumCapabilities
            putStrLn $ "workers: " ++ show nOfPipelines
            putStrLn $ "qsizePerWorker: " ++ show qsizePerWorker
            putStrLn . ("cache size: " ++) . show . Cache.size =<< getCache_ env
            putStrLn $ "requests: " ++ show size
            putStrLn $ "elapsed: " ++ show elapsed
            putStrLn $ "rate: " ++ show rate

getEnvB :: Config -> Log.PutLines -> IO (Env, IO EpochTime)
getEnvB Config{..} putLines = do
    tcache@(getSec, _) <- TimeCache.new
    let cacheConf = Cache.MemoConf maxCacheSize 1800 memoActions
          where
            memoLogLn = putLines Log.WARN Nothing . (: [])
            memoActions = Cache.MemoActions memoLogLn getSec
    memo <- Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
    env <- Iterative.newEnv putLines False (insert, Cache.readMemo memo) tcache
    return (env, getSec)

getPipelineB
    :: Bool
    -> Config
    -> Env
    -> IO EpochTime
    -> IO ([[IO ()]], Request () -> IO (), IO (Request ()))
getPipelineB True Config{..} _ _ = do
    let qsize = qsizePerWorker * nOfPipelines
    reqQ <- newQueue qsize
    resQ <- newQueue qsize
    let pipelines = replicate nOfPipelines [forever $ writeQueue resQ =<< readQueue reqQ]
    return (pipelines, writeQueue reqQ, readQueue resQ)
getPipelineB _ conf env getSec = do
    (workerPipelines, enqueueReq, dequeueRes) <-
        getWorkers conf getSec env
            :: IO ([IO ([IO ()], WorkerStatus)], Request () -> IO (), IO (Response ()))
    (workers, _getsStatus) <- unzip <$> sequence workerPipelines
    return (workers, enqueueReq, dequeueRes)

runQueriesB :: [a1] -> ((a1, ()) -> IO a2) -> IO a3 -> IO [a3]
runQueriesB qs enqueueReq dequeueResp = do
    _ <- forkIO $ sequence_ [enqueueReq (q, ()) | q <- qs]
    replicateM len dequeueResp
  where
    len = length qs
