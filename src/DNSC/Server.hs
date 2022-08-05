
module DNSC.Server (
  run,
  ) where

-- GHC packages
import Control.Concurrent (getNumCapabilities)
import Control.Monad ((<=<), forever)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Except (runExceptT, throwE)
import Data.List (uncons)
import Data.ByteString (ByteString)
import Data.IORef (newIORef, readIORef, atomicModifyIORef')

-- dns packages
import Network.Socket (AddrInfo (..), SocketType (Datagram), HostName, PortNumber, Socket, SockAddr)
import qualified Network.Socket as S
import qualified Network.DNS as DNS

-- other packages
import UnliftIO (SomeException, tryAny, concurrently_, race_)

-- this package
import DNSC.Queue (newQueue, readQueue, writeQueue, TQ)
import qualified DNSC.Queue as Queue
import DNSC.SocketUtil (addrInfo, isAnySockAddr)
import DNSC.DNSUtil (mkRecvBS, mkSendBS)
import DNSC.ServerMonitor (monitor, PLStatus)
import qualified DNSC.ServerMonitor as Mon
import DNSC.Types (Timestamp, NE)
import qualified DNSC.Log as Log
import qualified DNSC.TimeCache as TimeCache
import qualified DNSC.UpdateCache as UCache
import DNSC.Iterative (Context (..), newContext, getReplyCached, getReplyMessage)


type Request a = (ByteString, a)
type Decoded a = (DNS.DNSHeader, NE DNS.Question, a)
type Response a = (ByteString, a)

udpSockets :: PortNumber -> [HostName] -> IO [(Socket, SockAddr)]
udpSockets port = mapM aiSocket . filter ((== Datagram) . addrSocketType) <=< addrInfo port
  where
    aiSocket ai = (,) <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai) <*> pure (addrAddress ai)

run :: Bool -> Log.Output -> Log.Level -> Int -> Bool -> Int -> Int
    -> PortNumber -> [HostName] -> Bool -> IO ()
run fastLogger logOutput logLevel maxCacheSize disableV6NS workers qsizePerWorker port hosts stdConsole = do
  (serverLoops, sas, monLoops) <- setup fastLogger logOutput logLevel maxCacheSize disableV6NS workers qsizePerWorker port hosts stdConsole
  mapM_ (uncurry S.bind) sas
  race_
    (foldr concurrently_ (return ()) serverLoops)
    (foldr concurrently_ (return ()) monLoops)

setup :: Bool -> Log.Output -> Log.Level -> Int -> Bool -> Int -> Int
     -> PortNumber -> [HostName] -> Bool
     -> IO ([IO ()], [(Socket, SockAddr)], [IO ()])
setup fastLogger logOutput logLevel maxCacheSize disableV6NS workers qsizePerWorker port hosts stdConsole = do
  let getLogger
        | fastLogger = do
            (putLines, logQSize, flushLog) <- Log.newFastLogger logOutput logLevel
            return ([], putLines, logQSize, flushLog)
        | otherwise  = do
            (logLoop, putLines, logQSize) <- Log.new (Log.outputHandle logOutput) logLevel
            return ([logLoop], putLines, logQSize, pure ())
  (logLoops, putLines, logQSize, flushLog) <- getLogger
  tcache@(getSec, _) <- TimeCache.new
  (ucacheLoops, insert, getCache, expires, ucacheQSize) <- UCache.new putLines tcache maxCacheSize
  cxt <- newContext putLines disableV6NS (insert, getCache) tcache

  sas <- udpSockets port hosts

  (pLoops, qsizes) <- do
    (loopsList, qsizes) <- unzip <$> mapM (uncurry $ getPipeline workers qsizePerWorker getSec cxt) sas
    return (concat loopsList, qsizes)

  caps <- getNumCapabilities
  let params = Mon.makeParams caps logOutput logLevel maxCacheSize disableV6NS workers qsizePerWorker port hosts
  putLines Log.NOTICE $ map ("params: " ++) $ Mon.showParams params

  monLoops <- monitor stdConsole params cxt (qsizes, ucacheQSize, logQSize) expires flushLog

  return (logLoops ++ ucacheLoops ++ pLoops, sas, monLoops)

getPipeline :: Int -> Int -> IO Timestamp -> Context -> Socket -> SockAddr
            -> IO ([IO ()], PLStatus)
getPipeline workers perWorker getSec cxt sock_ addr_ = do
  let putLn lv = logLines_ cxt lv . (:[])
      wildcard = isAnySockAddr addr_
      send bs (peer, cmsgs) = mkSendBS wildcard sock_ bs peer cmsgs
      recv = mkRecvBS wildcard sock_
      resolvWorkers = workers * 8
      queueSize = workers * perWorker
  (getHit, incHit) <- counter
  (getMiss, incMiss) <- counter
  (getFailed, incFailed) <- counter

  (respLoop, enqueueResp, resQSize) <- consumeLoop queueSize (putLn Log.NOTICE . ("Server.sendResponse: error: " ++) . show) $ sendResponse send cxt
  (resolvLoop, enqueueDec, decQSize) <- consumeLoop queueSize (putLn Log.NOTICE . ("Server.resolvWorker: error: " ++) . show) $ resolvWorker cxt incMiss incFailed  enqueueResp
  (cachedLoop, enqueueReq, reqQSize) <- consumeLoop queueSize (putLn Log.NOTICE . ("Server.cachedWorker: error: " ++) . show) $ cachedWorker cxt getSec incHit incFailed enqueueDec enqueueResp
  let resolvLoops = replicate resolvWorkers resolvLoop
      cachedLoops = replicate workers cachedLoop
      reqLoop = handledLoop (putLn Log.NOTICE . ("Server.recvRequest: error: " ++) . show)
                $ recvRequest recv cxt enqueueReq
  return (respLoop : resolvLoops ++ cachedLoops ++ [reqLoop], (reqQSize, decQSize, resQSize, getHit, getMiss, getFailed))

type WorkerStatus = (IO (Int, Int), IO (Int, Int), IO (Int, Int), IO Int, IO Int, IO Int)

workerPipeline :: Show a
               => TQ (Request a) -> TQ (Response a)
               -> Int -> IO Timestamp -> Context
               -> IO ([IO ()], WorkerStatus)
workerPipeline reqQ resQ perWorker getSec cxt = do
  let putLn lv = logLines_ cxt lv . (:[])
      resolvWorkers = 8
  (getHit, incHit) <- counter
  (getMiss, incMiss) <- counter
  (getFailed, incFailed) <- counter

  let enqueueResp = writeQueue resQ
      resQSize = (,) <$> (fst <$> Queue.readSizes resQ) <*> pure (Queue.sizeMaxBound resQ)

  (resolvLoop, enqueueDec, decQSize) <- consumeLoop perWorker (putLn Log.NOTICE . ("Server.resolvWorker: error: " ++) . show)
                                        $ resolvWorker cxt incMiss incFailed enqueueResp
  let cachedLoop = readLoop (readQueue reqQ) (putLn Log.NOTICE . ("Server.cachedWorker: error: " ++) . show)
                   $ cachedWorker cxt getSec incHit incFailed enqueueDec enqueueResp
      reqQSize = (,) <$> (fst <$> Queue.readSizes reqQ) <*> pure (Queue.sizeMaxBound reqQ)
      resolvLoops = replicate resolvWorkers resolvLoop

  return (resolvLoops ++ [cachedLoop], (reqQSize, decQSize, resQSize, getHit, getMiss, getFailed))

recvRequest :: Show a
            => IO (ByteString, a)
            -> Context
            -> (Request a -> IO ())
            -> IO ()
recvRequest recv _cxt enqReq = do
  (bs, addr) <- recv
  enqReq (bs, addr)

cachedWorker :: Show a
             => Context
             -> IO Timestamp
             -> IO ()
             -> IO ()
             -> (Decoded a -> IO ())
             -> (Response a -> IO ())
             -> Request a -> IO ()
cachedWorker cxt getSec incHit incFailed enqDec enqResp (bs, addr) =
  either (logLn Log.NOTICE) return <=< runExceptT $ do
  let decode = do
        now <- liftIO getSec
        msg <- either (throwE . ("decode-error: " ++) . show) return $ DNS.decodeAt now bs
        qs <- maybe (throwE $ "empty question ignored: " ++ show addr) return $ uncons $ DNS.question msg
        return (qs, msg)
  (qs@(q, _), reqM) <- decode
  let reqH = DNS.header reqM
      enqueueDec = liftIO $ reqH `seq` qs `seq` enqDec (reqH, qs, addr)
      noResponse replyErr = liftIO incFailed >> throwE ("cached: response cannot be generated: " ++ replyErr ++ ": " ++ show (q, addr))
      enqueue respM = liftIO $ do
        incHit
        let rbs = DNS.encode respM
        rbs `seq` enqResp (rbs, addr)
  maybe enqueueDec (either noResponse enqueue) =<< liftIO (getReplyCached cxt reqH qs)
  where
    logLn level = logLines_ cxt level . (:[])

resolvWorker :: Show a
             => Context
             -> IO ()
             -> IO ()
             -> (Response a -> IO ())
             -> Decoded a -> IO ()
resolvWorker cxt incMiss incFailed enqResp (reqH, qs@(q, _), addr) =
  either (logLn Log.NOTICE) return <=< runExceptT $ do
  let noResponse replyErr = liftIO incFailed >> throwE ("resolv: response cannot be generated: " ++ replyErr ++ ": " ++ show (q, addr))
      enqueue respM = liftIO $ do
        incMiss
        let rbs = DNS.encode respM
        rbs `seq` enqResp (rbs, addr)
  either noResponse enqueue =<< liftIO (getReplyMessage cxt reqH qs)
  where
    logLn level = logLines_ cxt level . (:[])

sendResponse :: (ByteString -> a -> IO ())
             -> Context
             -> Response a -> IO ()
sendResponse send _cxt (bs, addr) = send bs addr

---

consumeLoop :: Int
            -> (SomeException -> IO ())
            -> (a -> IO ())
            -> IO (IO b, a -> IO (), IO (Int, Int))
consumeLoop qsize onError body = do
  inQ <- newQueue qsize
  let loop = readLoop (readQueue inQ) onError body
      sizeInfo = (,) <$> (fst <$> Queue.readSizes inQ) <*> pure (Queue.sizeMaxBound inQ)
  return (loop, writeQueue inQ, sizeInfo)

readLoop :: IO a
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
