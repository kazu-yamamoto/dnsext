{-# LANGUAGE ParallelListComp #-}

module DNS.Cache.Server (
    run,
    workerBenchmark,
) where

-- GHC packages
import Control.Concurrent (forkIO, getNumCapabilities)
import Control.DeepSeq (deepseq)
import Control.Monad (forever, replicateM)
import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)
import Data.IORef (atomicModifyIORef', newIORef, readIORef)
import Data.List (uncons)
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

import DNS.Cache.Iterative (Env (..), getReplyCached, getReplyMessage)
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
import DNS.Cache.Types (NE)
import qualified DNS.Log as Log

type Request a = (ByteString, a)
type Decoded a = (DNS.DNSHeader, DNS.EDNSheader, NE DNS.Question, a)
type Response a = (ByteString, a)

----------------------------------------------------------------

run
    :: Log.Output
    -> Log.Level
    -> Int
    -> Bool
    -> Int
    -> Bool
    -> Int
    -> PortNumber
    -> [HostName]
    -> Bool
    -> IO ()
run logOutput logLevel maxCacheSize disableV6NS n workerSharedQueue qsizePerWorker port hosts stdConsole = do
    DNS.runInitIO DNS.addResourceDataForDNSSEC
    (serverLoops, monLoops) <-
        setup
            logOutput
            logLevel
            maxCacheSize
            disableV6NS
            n
            workerSharedQueue
            qsizePerWorker
            port
            hosts
            stdConsole
    race_
        (foldr concurrently_ (return ()) serverLoops)
        (foldr concurrently_ (return ()) monLoops)

----------------------------------------------------------------

setup
    :: Log.Output
    -> Log.Level
    -> Int
    -> Bool
    -> Int
    -> Bool
    -> Int
    -> PortNumber
    -> [HostName]
    -> Bool
    -> IO ([IO ()], [IO ()])
setup logOutput logLevel maxCacheSize disableV6NS n workerSharedQueue qsizePerWorker port hosts stdConsole = do
    (putLines, logQSize, terminate) <- Log.new logOutput logLevel
    (env, getSec, expires) <- getEnv maxCacheSize disableV6NS putLines
    hostIPs <- getHostIPs hosts port

    let getP = getPipeline n workerSharedQueue qsizePerWorker getSec env port
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
            n
            workerSharedQueue
            qsizePerWorker
            port
            hosts

----------------------------------------------------------------

getEnv
    :: Int -> Bool -> Log.PutLines -> IO (Env, IO EpochTime, EpochTime -> IO ())
getEnv maxCacheSize disableV6NS putLines = do
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

getPipeline
    :: Int
    -> Bool
    -> Int
    -> IO EpochTime
    -> Env
    -> PortNumber
    -> IP
    -> IO ([IO ()], PLStatus)
getPipeline n sharedQueue perWorker getSec env port hostIP = do
    sock <- UDP.serverSocket (hostIP, port)
    let putLn lv = logLines_ env lv Nothing . (: [])

    (workerPipelines, enqueueReq, dequeueResp) <-
        getWorkers n sharedQueue perWorker getSec env
    (workers, getsStatus) <- unzip <$> sequence workerPipelines

    let onErrorR = putLn Log.WARN . ("Server.recvRequest: error: " ++) . show
        receiver = handledLoop onErrorR (UDP.recvFrom sock >>= enqueueReq)

    let onErrorS = putLn Log.WARN . ("Server.sendResponse: error: " ++) . show
        sender = handledLoop onErrorS (dequeueResp >>= uncurry (UDP.sendTo sock))
    return (receiver : sender : concat workers, getsStatus)

----------------------------------------------------------------

getWorkers
    :: Show a
    => Int
    -> Bool
    -> Int
    -> IO EpochTime
    -> Env
    -> IO ([IO ([IO ()], WorkerStatus)], Request a -> IO (), IO (Response a))
getWorkers n sharedQueue perWorker getSec env
    | perWorker <= 0 = do
        reqQ <- newQueueChan
        resQ <- newQueueChan
        {- share request queue and response queue -}
        let wps = replicate n $ getSenderReceiver reqQ resQ 8 getSec env
        return (wps, writeQueue reqQ, readQueue resQ)
    | sharedQueue = do
        let qsize = perWorker * n
        reqQ <- newQueue qsize
        resQ <- newQueue qsize
        {- share request queue and response queue -}
        let wps = replicate n $ getSenderReceiver reqQ resQ perWorker getSec env
        return (wps, writeQueue reqQ, readQueue resQ)
    | otherwise = do
        reqQs <- replicateM n $ newQueue perWorker
        enqueueReq <- Queue.writeQueue <$> Queue.makePutAny reqQs
        resQs <- replicateM n $ newQueue perWorker
        dequeueResp <- Queue.readQueue <$> Queue.makeGetAny resQs
        let wps =
                [ getSenderReceiver reqQ resQ perWorker getSec env
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
getSenderReceiver reqQ resQ perWorker getSec env = do
    (getHit, incHit) <- counter
    (getMiss, incMiss) <- counter
    (getFailed, incFailed) <- counter

    let logr = putLn Log.WARN . ("Server.resolvWorker: error: " ++) . show
        rslvWrkr = resolvWorker env incMiss incFailed enqueueResp
    (resolvLoop, enqueueDec, decQSize) <- consumeLoop perWorker logr rslvWrkr

    let logc = putLn Log.WARN . ("Server.cachedWorker: error: " ++) . show
        ccWrkr = cachedWorker env getSec incHit incFailed enqueueDec enqueueResp
        cachedLoop = handledLoop logc (readQueue reqQ >>= ccWrkr)

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

cachedWorker
    :: Show a
    => Env
    -> IO EpochTime
    -> IO ()
    -> IO ()
    -> (Decoded a -> IO ())
    -> (Response a -> IO ())
    -> Request a
    -> IO ()
cachedWorker env getSec incHit incFailed enqueueDec enqueueResp (bs, addr) = do
    now <- liftIO getSec
    case DNS.decodeAt now bs of
        Left e -> logLn Log.WARN $ "decode-error: " ++ show e
        Right reqM -> case uncons $ DNS.question reqM of
            Nothing -> logLn Log.WARN $ "empty question ignored: " ++ show addr
            Just qs@(q, _) -> do
                let reqH = DNS.header reqM
                    reqEH = DNS.ednsHeader reqM
                mx <- getReplyCached env reqH reqEH qs
                case mx of
                    Nothing ->
                        reqH `seq` reqEH `seq` qs `seq` enqueueDec (reqH, reqEH, qs, addr)
                    Just (Right respM) -> do
                        incHit
                        let rbs = DNS.encode respM
                        rbs `seq` enqueueResp (rbs, addr)
                    Just (Left replyErr) -> do
                        liftIO incFailed
                        logLn Log.WARN $
                            "cached: response cannot be generated: " ++ replyErr ++ ": " ++ show (q, addr)
  where
    logLn level = logLines_ env level Nothing . (: [])

----------------------------------------------------------------

resolvWorker
    :: Show a
    => Env
    -> IO ()
    -> IO ()
    -> (Response a -> IO ())
    -> Decoded a
    -> IO ()
resolvWorker env incMiss incFailed enqueueResp (reqH, reqEH, qs@(q, _), addr) = do
    ex <- getReplyMessage env reqH reqEH qs
    case ex of
        Right x -> do
            incMiss
            let rbs = DNS.encode x
            rbs `seq` enqueueResp (rbs, addr)
        Left e -> do
            incFailed
            logLn Log.WARN $
                "resolv: response cannot be generated: " ++ e ++ ": " ++ show (q, addr)
  where
    logLn level = logLines_ env level Nothing . (: [])

----------------------------------------------------------------

consumeLoop
    :: Int
    -> (SomeException -> IO ())
    -> (a -> IO ())
    -> IO (IO (), a -> IO (), IO (Int, Int))
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

workerBenchmark :: Bool -> Bool -> Int -> Int -> Int -> IO ()
workerBenchmark noop gplot n perWorker size = do
    (putLines, _logQSize, _terminate) <- Log.new Log.Stdout Log.WARN
    (env, getSec) <- getEnvB putLines

    (workers, enqueueReq, dequeueResp) <-
        getPipelineB noop n perWorker env getSec
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
            putStrLn $ unwords [show n, show rate]
        else do
            putStrLn . ("capabilities: " ++) . show =<< getNumCapabilities
            putStrLn $ "workers: " ++ show n
            putStrLn $ "perWorker: " ++ show perWorker
            putStrLn . ("cache size: " ++) . show . Cache.size =<< getCache_ env
            putStrLn $ "requests: " ++ show size
            putStrLn $ "elapsed: " ++ show elapsed
            putStrLn $ "rate: " ++ show rate

getEnvB :: Log.PutLines -> IO (Env, IO EpochTime)
getEnvB putLines = do
    tcache@(getSec, _) <- TimeCache.new
    let cacheConf = Cache.MemoConf (2 * 1024 * 1024) 1800 memoActions
          where
            memoLogLn = putLines Log.WARN Nothing . (: [])
            memoActions = Cache.MemoActions memoLogLn getSec
    memo <- Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
    env <- Iterative.newEnv putLines False (insert, Cache.readMemo memo) tcache
    return (env, getSec)

getPipelineB
    :: Bool
    -> Int
    -> Int
    -> Env
    -> IO EpochTime
    -> IO ([[IO ()]], Request () -> IO (), IO (Request ()))
getPipelineB True n perWorker _ _ = do
    let qsize = perWorker * n
    reqQ <- newQueue qsize
    resQ <- newQueue qsize
    let pipelines = replicate n [forever $ writeQueue resQ =<< readQueue reqQ]
    return (pipelines, writeQueue reqQ, readQueue resQ)
getPipelineB _ n perWorker env getSec = do
    (workerPipelines, enqueueReq, dequeueRes) <-
        getWorkers n True perWorker getSec env
            :: IO ([IO ([IO ()], WorkerStatus)], Request () -> IO (), IO (Response ()))
    (workers, _getsStatus) <- unzip <$> sequence workerPipelines
    return (workers, enqueueReq, dequeueRes)

runQueriesB :: [a1] -> ((a1, ()) -> IO a2) -> IO a3 -> IO [a3]
runQueriesB qs enqueueReq dequeueResp = do
    _ <- forkIO $ sequence_ [enqueueReq (q, ()) | q <- qs]
    replicateM len dequeueResp
  where
    len = length qs
