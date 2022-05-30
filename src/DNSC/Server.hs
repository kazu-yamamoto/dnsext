
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

-- dns packages
import Network.Socket (AddrInfo (..), SocketType (Datagram), HostName, PortNumber, Socket, SockAddr)
import qualified Network.Socket as S
import qualified Network.DNS as DNS

-- other packages
import UnliftIO (SomeException, tryAny, concurrently_, race_)

-- this package
import DNSC.Queue (newQueue, readQueue, writeQueue)
import qualified DNSC.Queue as Queue
import DNSC.SocketUtil (addrInfo, isAnySockAddr)
import DNSC.DNSUtil (mkRecvBS, mkSendBS)
import DNSC.ServerMonitor (monitor)
import qualified DNSC.ServerMonitor as Mon
import DNSC.Types (Timestamp)
import qualified DNSC.Log as Log
import qualified DNSC.TimeCache as TimeCache
import qualified DNSC.UpdateCache as UCache
import DNSC.Iterative (Context (..), newContext, getReplyMessage)


type Request s a = (s, ByteString, a)
type Response s a = ((s, ByteString), a)

udpSockets :: PortNumber -> [HostName] -> IO [(Socket, SockAddr)]
udpSockets port = mapM aiSocket . filter ((== Datagram) . addrSocketType) <=< addrInfo port
  where
    aiSocket ai = (,) <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai) <*> pure (addrAddress ai)

run :: Log.FOutput -> Log.Level -> Int -> Bool -> Int
    -> PortNumber -> [HostName] -> Bool -> IO ()
run logOutput logLevel maxCacheSize disableV6NS conc port hosts stdConsole = do
  caps <- getNumCapabilities
  let params = Mon.makeParams caps logOutput logLevel maxCacheSize disableV6NS conc (fromIntegral port) hosts
  (serverLoops, monArgs) <- setup logOutput logLevel maxCacheSize disableV6NS conc port hosts $ Mon.showParams params
  monLoops <- uncurry (uncurry $ monitor stdConsole params) monArgs
  race_
    (foldr concurrently_ (return ()) serverLoops)
    (foldr concurrently_ (return ()) monLoops)

type QSizeInfo = (IO (Int, Int), IO (Int, Int), IO (Int, Int), IO (Int, Int))

setup :: Log.FOutput -> Log.Level -> Int -> Bool -> Int
     -> PortNumber -> [HostName]
     -> [String]
     -> IO ([IO ()], ((Context, QSizeInfo), IO ()))
setup logOutput logLevel maxCacheSize disableV6NS conc port hosts paramLogs = do
  (putLines, logQSize, flushLog) <- Log.newFastLogger logOutput logLevel
  tcache@(getSec, _) <- TimeCache.new
  (ucacheLoops, ucache, ucacheQSize) <- UCache.new putLines tcache maxCacheSize
  cxt <- newContext putLines disableV6NS ucache tcache

  putLines Log.NOTICE $ map ("params: " ++) paramLogs

  sas <- udpSockets port hosts

  let putLn lv = putLines lv . (:[])
      send sock bs (peer, cmsgs, wildcard) = mkSendBS wildcard sock bs peer cmsgs

  (respLoop, enqueueResp, resQSize) <- consumeLoop 8 (putLn Log.NOTICE . ("Server.sendResponse: error: " ++) . show) $ sendResponse send cxt
  (procLoop, enqueueReq, reqQSize) <- consumeLoop (8 `max` conc) (putLn Log.NOTICE . ("Server.processRequest: error: " ++) . show) $ processRequest cxt getSec enqueueResp
  let procLoops = replicate conc procLoop

      reqLoops =
        [ handledLoop (putLn Log.NOTICE . ("Server.recvRequest: error: " ++) . show)
          $ recvRequest (mkRecvBS $ isAnySockAddr addr) cxt enqueueReq sock
        | (sock, addr) <- sas
        ]

  mapM_ (uncurry S.bind) sas

  return (ucacheLoops ++ respLoop : procLoops ++ reqLoops, ((cxt, (reqQSize, resQSize, ucacheQSize, logQSize)), flushLog))

recvRequest :: Show a
            => (s -> IO (ByteString, a))
            -> Context
            -> (Request s a -> IO ())
            -> s
            -> IO ()
recvRequest recv _cxt enqReq sock = do
  (bs, addr) <- recv sock
  enqReq (sock, bs, addr)

processRequest :: Show a
               => Context
               -> IO Timestamp
               -> (Response s a -> IO ())
               -> Request s a -> IO ()
processRequest cxt getSec enqResp (sock, bs, addr) =
  (either (logLn Log.NOTICE) return =<<) . runExceptT $ do
  let decode = do
        now <- liftIO $ getSec
        msg <- either (throwE . ("dns-error: " ++) . show) return $ DNS.decodeAt now bs
        qs <- maybe (throwE $ "empty question ignored: " ++ show addr) return $ uncons $ DNS.question msg
        return (qs, msg)
  (qs@(q, _), reqM) <- decode

  let mkReply = do
        let noResponse replyErr = "response cannot be generated: " ++ replyErr ++ ": " ++ show (q, addr)
        either (throwE . noResponse) return =<< liftIO (getReplyMessage cxt (DNS.header reqM) qs)
      enqueue respM = do
        let rbs = DNS.encode respM
        rbs `seq` enqResp ((sock, rbs), addr)
  liftIO . enqueue =<< mkReply
  where
    logLn level = logLines_ cxt level . (:[])

sendResponse :: (s -> ByteString -> a -> IO ())
             -> Context
             -> Response s a -> IO ()
sendResponse send _cxt = uncurry (uncurry send)

---

consumeLoop :: Int
            -> (SomeException -> IO ()) -> (a -> IO ())
            -> IO (IO b, a -> IO (), IO (Int, Int))
consumeLoop qsize onError body = do
  inQ <- newQueue qsize
  let enqueue = writeQueue inQ
      hbody = either onError return <=< tryAny . body
      loop = forever $ hbody =<< readQueue inQ

  return (loop, enqueue, (,) <$> Queue.readSize inQ <*> pure (Queue.maxSize inQ))

handledLoop :: (SomeException -> IO ()) -> IO () -> IO a
handledLoop onError = forever . handle
  where
    handle = either onError return <=< tryAny
