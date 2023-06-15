{-# LANGUAGE ParallelListComp #-}

module DNS.Cache.Server (
    run,
    workerBenchmark,
) where

-- GHC packages
import Control.Concurrent (forkIO, getNumCapabilities)
import Control.DeepSeq (deepseq)
import Control.Monad (forever, replicateM, (<=<))
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
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
import UnliftIO (SomeException, concurrently_, race_, tryAny)

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
import DNS.Cache.ServerMonitor (PLStatus, WorkerStatus(WorkerStatus), monitor)
import qualified DNS.Cache.ServerMonitor as Mon
import qualified DNS.Cache.TimeCache as TimeCache
import DNS.Cache.Types (NE)
import qualified DNS.Log as Log

type Request a = (ByteString, a)
type Decoded a = (DNS.DNSHeader, DNS.EDNSheader, NE DNS.Question, a)
type Response a = (ByteString, a)

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
run logOutput logLevel maxCacheSize disableV6NS workers workerSharedQueue qsizePerWorker port hosts stdConsole = do
    DNS.runInitIO DNS.addResourceDataForDNSSEC
    (serverLoops, monLoops) <-
        setup
            logOutput
            logLevel
            maxCacheSize
            disableV6NS
            workers
            workerSharedQueue
            qsizePerWorker
            port
            hosts
            stdConsole
    race_
        (foldr concurrently_ (return ()) serverLoops)
        (foldr concurrently_ (return ()) monLoops)

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
setup logOutput logLevel maxCacheSize disableV6NS workers workerSharedQueue qsizePerWorker port hosts stdConsole = do
    (putLines, logQSize, terminate) <- Log.new logOutput logLevel
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
    cxt <-
        Iterative.newEnv putLines disableV6NS (insert, Cache.readMemo memo) tcache

    let getAInfoIPs = do
            ais <- getAddrInfo Nothing Nothing (Just $ show port)
            let dgramIP AddrInfo{addrAddress = SockAddrInet _ ha} = Just $ IPv4 $ fromHostAddress ha
                dgramIP AddrInfo{addrAddress = SockAddrInet6 _ _ ha6 _} = Just $ IPv6 $ fromHostAddress6 ha6
                dgramIP _ = Nothing
            return $
                mapMaybe dgramIP [ai | ai@AddrInfo{addrSocketType = Datagram} <- ais]
    hostIPs <-
        if null hosts
            then getAInfoIPs
            else return $ map fromString hosts

    (pLoops, qsizes) <- do
        (loopsList, qsizes) <-
            unzip
                <$> mapM
                    (getPipeline workers workerSharedQueue qsizePerWorker getSec cxt port)
                    hostIPs
        return (concat loopsList, qsizes)

    caps <- getNumCapabilities
    let params =
            Mon.makeParams
                caps
                logOutput
                logLevel
                maxCacheSize
                disableV6NS
                workers
                workerSharedQueue
                qsizePerWorker
                port
                hosts
    putLines Log.WARN Nothing $ map ("params: " ++) $ Mon.showParams params

    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
    monLoops <-
        monitor stdConsole params cxt (qsizes, ucacheQSize, logQSize) expires terminate

    return (pLoops, monLoops)

getPipeline
    :: Int
    -> Bool
    -> Int
    -> IO EpochTime
    -> Env
    -> PortNumber
    -> IP
    -> IO ([IO ()], PLStatus)
getPipeline workers sharedQueue perWorker getSec cxt port hostIP = do
    sock <- UDP.serverSocket (hostIP, port)
    let putLn lv = logLines_ cxt lv Nothing . (: [])

    (workerPipelines, enqueueReq, dequeueResp) <-
        getWorkers workers sharedQueue perWorker getSec cxt
    (workerLoops, getsStatus) <- unzip <$> sequence workerPipelines

    let reqLoop =
            handledLoop (putLn Log.WARN . ("Server.recvRequest: error: " ++) . show) $
                recvRequest (UDP.recvFrom sock) cxt enqueueReq

    let respLoop =
            readLoop
                dequeueResp
                (putLn Log.WARN . ("Server.sendResponse: error: " ++) . show)
                $ sendResponse (UDP.sendTo sock) cxt

    return (respLoop : concat workerLoops ++ [reqLoop], getsStatus)

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

workerBenchmark :: Bool -> Bool -> Int -> Int -> Int -> IO ()
workerBenchmark noop gplot workers perWorker size = do
    (putLines, _logQSize, _terminate) <-
        Log.new Log.Stdout Log.WARN
    tcache@(getSec, _) <- TimeCache.new
    let cacheConf = Cache.MemoConf (2 * 1024 * 1024) 1800 memoActions
          where
            memoLogLn = putLines Log.WARN Nothing . (: [])
            memoActions = Cache.MemoActions memoLogLn getSec
    memo <- Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
    cxt <- Iterative.newEnv putLines False (insert, Cache.readMemo memo) tcache

    let getPipieline
            | noop = do
                let qsize = perWorker * workers
                reqQ <- newQueue qsize
                resQ <- newQueue qsize
                let pipelines = replicate workers [forever $ writeQueue resQ =<< readQueue reqQ]
                return (pipelines, writeQueue reqQ, readQueue resQ)
            | otherwise = do
                (workerPipelines, enqReq, deqRes) <-
                    getWorkers workers True perWorker getSec cxt
                        :: IO ([IO ([IO ()], WorkerStatus)], Request () -> IO (), IO (Response ()))
                (workerLoops, _getsStatus) <- unzip <$> sequence workerPipelines
                return (workerLoops, enqReq, deqRes)

    (workerLoops, enqueueReq, dequeueResp) <- getPipieline
    _ <- forkIO $ foldr concurrently_ (return ()) $ concat workerLoops

    let runQueries qs = do
            let len = length qs
            _ <- forkIO $ sequence_ [enqueueReq (q, ()) | q <- qs]
            replicateM len dequeueResp
        (initD, ds) = splitAt 4 $ take (4 + size) benchQueries

    ds `deepseq` return ()

    -----
    _ <- runQueries initD
    before <- getCurrentTime
    _ <- runQueries ds
    after <- getCurrentTime

    let elapsed = after `diffUTCTime` before
        toDouble = fromRational . toRational :: NominalDiffTime -> Double
        rate = toDouble $ fromIntegral size / after `diffUTCTime` before

    if gplot
        then do
            putStrLn $ unwords [show workers, show rate]
        else do
            putStrLn . ("capabilities: " ++) . show =<< getNumCapabilities
            putStrLn $ "workers: " ++ show workers
            putStrLn $ "perWorker: " ++ show perWorker
            putStrLn . ("cache size: " ++) . show . Cache.size =<< getCache_ cxt
            putStrLn $ "requests: " ++ show size
            putStrLn $ "elapsed: " ++ show elapsed
            putStrLn $ "rate: " ++ show rate

getWorkers
    :: Show a
    => Int
    -> Bool
    -> Int
    -> IO EpochTime
    -> Env
    -> IO ([IO ([IO ()], WorkerStatus)], Request a -> IO (), IO (Response a))
getWorkers workers sharedQueue perWorker getSec cxt
    | perWorker <= 0 = do
        reqQ <- newQueueChan
        resQ <- newQueueChan
        {- share request queue and response queue -}
        let wps = replicate workers $ workerPipeline reqQ resQ 8 getSec cxt
        return (wps, writeQueue reqQ, readQueue resQ)
    | sharedQueue = do
        let qsize = perWorker * workers
        reqQ <- newQueue qsize
        resQ <- newQueue qsize
        {- share request queue and response queue -}
        let wps = replicate workers $ workerPipeline reqQ resQ perWorker getSec cxt
        return (wps, writeQueue reqQ, readQueue resQ)
    | otherwise = do
        reqQs <- replicateM workers $ newQueue perWorker
        enqueueReq <- Queue.writeQueue <$> Queue.makePutAny reqQs
        resQs <- replicateM workers $ newQueue perWorker
        dequeueResp <- Queue.readQueue <$> Queue.makeGetAny resQs
        let wps =
                [ workerPipeline reqQ resQ perWorker getSec cxt
                | reqQ <- reqQs
                | resQ <- resQs
                ]
        return (wps, enqueueReq, dequeueResp)

workerPipeline
    :: (Show a, ReadQueue q1, QueueSize q1, WriteQueue q2, QueueSize q2)
    => q1 (Request a)
    -> q2 (Response a)
    -> Int
    -> IO EpochTime
    -> Env
    -> IO ([IO ()], WorkerStatus)
workerPipeline reqQ resQ perWorker getSec cxt = do
    let putLn lv = logLines_ cxt lv Nothing . (: [])
        resolvWorkers = 8
    (getHit, incHit) <- counter
    (getMiss, incMiss) <- counter
    (getFailed, incFailed) <- counter

    let enqueueResp = writeQueue resQ
        resQSize = (,) <$> (fst <$> Queue.readSizes resQ) <*> pure (Queue.sizeMaxBound resQ)

    (resolvLoop, enqueueDec, decQSize) <-
        consumeLoop
            perWorker
            (putLn Log.WARN . ("Server.resolvWorker: error: " ++) . show)
            $ resolvWorker cxt incMiss incFailed enqueueResp
    let cachedLoop =
            readLoop
                (readQueue reqQ)
                (putLn Log.WARN . ("Server.cachedWorker: error: " ++) . show)
                $ cachedWorker cxt getSec incHit incFailed enqueueDec enqueueResp
        reqQSize = (,) <$> (fst <$> Queue.readSizes reqQ) <*> pure (Queue.sizeMaxBound reqQ)
        resolvLoops = replicate resolvWorkers resolvLoop

    return
        ( resolvLoops ++ [cachedLoop]
        , WorkerStatus reqQSize decQSize resQSize getHit getMiss getFailed
        )

recvRequest
    :: Show a
    => IO (ByteString, a)
    -> Env
    -> (Request a -> IO ())
    -> IO ()
recvRequest recv _cxt enqReq = do
    (bs, addr) <- recv
    enqReq (bs, addr)

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
cachedWorker cxt getSec incHit incFailed enqDec enqResp (bs, addr) =
    either (logLn Log.WARN) return <=< runExceptT $ do
        let decode = do
                now <- liftIO getSec
                msg <-
                    either (throwE . ("decode-error: " ++) . show) return $ DNS.decodeAt now bs
                qs <-
                    maybe (throwE $ "empty question ignored: " ++ show addr) return $
                        uncons $
                            DNS.question msg
                return (qs, msg)
        (qs@(q, _), reqM) <- decode
        let reqH = DNS.header reqM
            reqEH = DNS.ednsHeader reqM
            enqueueDec = liftIO $ reqH `seq` reqEH `seq` qs `seq` enqDec (reqH, reqEH, qs, addr)
            noResponse replyErr =
                liftIO incFailed
                    >> throwE
                        ("cached: response cannot be generated: " ++ replyErr ++ ": " ++ show (q, addr))
            enqueue respM = liftIO $ do
                incHit
                let rbs = DNS.encode respM
                rbs `seq` enqResp (rbs, addr)
        maybe enqueueDec (either noResponse enqueue)
            =<< liftIO (getReplyCached cxt reqH reqEH qs)
  where
    logLn level = logLines_ cxt level Nothing . (: [])

resolvWorker
    :: Show a
    => Env
    -> IO ()
    -> IO ()
    -> (Response a -> IO ())
    -> Decoded a
    -> IO ()
resolvWorker cxt incMiss incFailed enqResp (reqH, reqEH, qs@(q, _), addr) =
    either (logLn Log.WARN) return <=< runExceptT $ do
        let noResponse replyErr =
                liftIO incFailed
                    >> throwE
                        ("resolv: response cannot be generated: " ++ replyErr ++ ": " ++ show (q, addr))
            enqueue respM = liftIO $ do
                incMiss
                let rbs = DNS.encode respM
                rbs `seq` enqResp (rbs, addr)
        either noResponse enqueue =<< liftIO (getReplyMessage cxt reqH reqEH qs)
  where
    logLn level = logLines_ cxt level Nothing . (: [])

sendResponse
    :: (ByteString -> a -> IO ())
    -> Env
    -> Response a
    -> IO ()
sendResponse send _cxt (bs, addr) = send bs addr

---

consumeLoop
    :: Int
    -> (SomeException -> IO ())
    -> (a -> IO ())
    -> IO (IO b, a -> IO (), IO (Int, Int))
consumeLoop qsize onError body = do
    inQ <- newQueue qsize
    let loop = readLoop (readQueue inQ) onError body
        sizeInfo = (,) <$> (fst <$> Queue.readSizes inQ) <*> pure (Queue.sizeMaxBound inQ)
    return (loop, writeQueue inQ, sizeInfo)

readLoop
    :: IO a
    -> (SomeException -> IO ())
    -> (a -> IO ())
    -> IO b
readLoop readQ onError body = loop
  where
    hbody = either onError return <=< tryAny . body
    loop = forever $ hbody =<< readQ

handledLoop :: (SomeException -> IO ()) -> IO () -> IO a
handledLoop onError = forever . handle
  where
    handle = either onError return <=< tryAny

counter :: IO (IO Int, IO ())
counter = do
    ref <- newIORef 0
    return (readIORef ref, atomicModifyIORef' ref (\x -> (x + 1, ())))
