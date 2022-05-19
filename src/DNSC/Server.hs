
module DNSC.Server (
  run,
  ) where

-- GHC packages
import Control.Concurrent (getNumCapabilities)
import Control.Monad ((<=<), forever)
import Data.List (uncons)
import System.IO.Error (tryIOError)

-- dns packages
import Control.Concurrent.Async (concurrently_, race_)
import Network.Socket (AddrInfo (..), SocketType (Datagram), HostName, PortNumber, Socket, SockAddr)
import qualified Network.Socket as S
import Network.DNS (DNSMessage, DNSHeader, Question)
import qualified Network.DNS as DNS

-- this package
import DNSC.Queue (newQueue, readQueue, writeQueue)
import qualified DNSC.Queue as Queue
import DNSC.SocketUtil (addrInfo, isAnySockAddr)
import DNSC.DNSUtil (mkRecv, mkSend)
import DNSC.ServerMonitor (monitor)
import qualified DNSC.ServerMonitor as Mon
import DNSC.Types (NE)
import qualified DNSC.Log as Log
import qualified DNSC.TimeCache as TimeCache
import qualified DNSC.UpdateCache as UCache
import DNSC.Iterative (Context (..), newContext, runReply)


type Request s a = (s, (DNSHeader, NE Question), a)
type Response s a = ((s, DNSMessage), a)

udpSockets :: PortNumber -> [HostName] -> IO [(Socket, SockAddr)]
udpSockets port = mapM aiSocket . filter ((== Datagram) . addrSocketType) <=< addrInfo port
  where
    aiSocket ai = (,) <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai) <*> pure (addrAddress ai)

run :: Log.FOutput -> Log.Level -> Int -> Bool -> Int
    -> PortNumber -> [HostName] -> Bool -> IO ()
run logOutput logLevel maxCacheSize disableV6NS conc port hosts stdConsole = do
  (serverLoops, monParams) <- bind logOutput logLevel maxCacheSize disableV6NS conc port hosts
  monLoops <- uncurry (uncurry $ uncurry $ monitor stdConsole) monParams
  race_
    (foldr concurrently_ (return ()) serverLoops)
    (foldr concurrently_ (return ()) monLoops)

type QSizeInfo = (IO (Int, Int), IO (Int, Int), IO (Int, Int), IO (Int, Int))

bind :: Log.FOutput -> Log.Level -> Int -> Bool -> Int
     -> PortNumber -> [HostName]
     -> IO ([IO ()], (((Mon.Params, Context), QSizeInfo), IO ()))
bind logOutput logLevel maxCacheSize disableV6NS conc port hosts = do
  (putLines, logQSize, flushLog) <- Log.newFastLogger logOutput logLevel
  tcache@(getSec, _) <- TimeCache.new
  (ucacheLoops, ucache, ucacheQSize) <- UCache.new putLines tcache maxCacheSize
  cxt <- newContext putLines disableV6NS ucache tcache

  params <- do
    cap <- getNumCapabilities
    return $ Mon.makeParams cap logOutput logLevel maxCacheSize disableV6NS conc (fromIntegral port) hosts
  putLines Log.NOTICE $ map ("params: " ++) $ Mon.showParams params

  sas <- udpSockets port hosts

  let putLn lv = putLines lv . (:[])
      send sock msg (peer, cmsgs, wildcard) = mkSend wildcard sock msg peer cmsgs

  (respLoop, enqueueResp, resQSize) <- consumeLoop 8 (putLn Log.NOTICE . ("Server.sendResponse: error: " ++) . show) $ sendResponse send cxt
  (procLoop, enqueueReq, reqQSize) <- consumeLoop (8 `max` conc) (putLn Log.NOTICE . ("Server.processRequest: error: " ++) . show) $ processRequest cxt enqueueResp
  let procLoops = replicate conc procLoop

      reqLoops =
        [ handledLoop (putLn Log.NOTICE . ("Server.recvRequest: error: " ++) . show)
          $ recvRequest recv cxt enqueueReq sock
        | (sock, addr) <- sas
        , let wildcard = isAnySockAddr addr
              recv s = do
                now <- getSec
                mkRecv wildcard now s
        ]

  mapM_ (uncurry S.bind) sas

  return (ucacheLoops ++ respLoop : procLoops ++ reqLoops, (((params, cxt), (reqQSize, resQSize, ucacheQSize, logQSize)), flushLog))

recvRequest :: Show a
            => (s -> IO (DNSMessage, a))
            -> Context
            -> (Request s a -> IO ())
            -> s
            -> IO ()
recvRequest recv cxt enqReq sock = do
  (m, addr) <- recv sock
  let logLn level = logLines_ cxt level . (:[])
      enqueue qs = enqReq (sock, (DNS.header m, qs), addr)
      emptyWarn = logLn Log.NOTICE $ "empty question ignored: " ++ show addr
  maybe emptyWarn enqueue $ uncons $ DNS.question m

processRequest :: Show a
               => Context
               -> (Response s a -> IO ())
               -> Request s a -> IO ()
processRequest cxt enqResp (sock, rp@(_, (q,_)), addr) = do
  let enqueue m = enqResp ((sock, m), addr)
      logLn level = logLines_ cxt level . (:[])
      noResponse replyErr = logLn Log.NOTICE $ "response cannot be generated: " ++ replyErr ++ ": " ++ show (q, addr)
  either noResponse enqueue =<< uncurry (runReply cxt) rp

sendResponse :: (s -> DNSMessage -> a -> IO ())
             -> Context
             -> Response s a -> IO ()
sendResponse send _cxt = uncurry (uncurry send)

---

consumeLoop :: Int
            -> (IOError -> IO ()) -> (a -> IO ())
            -> IO (IO b, a -> IO (), IO (Int, Int))
consumeLoop qsize onError body = do
  inQ <- newQueue qsize
  let enqueue = writeQueue inQ
      hbody = either onError return <=< tryIOError . body
      loop = forever $ hbody =<< readQueue inQ

  return (loop, enqueue, (,) <$> Queue.readSize inQ <*> pure (Queue.maxSize inQ))

handledLoop :: (IOError -> IO a) -> IO a -> IO b
handledLoop onError = forever . handle
  where
    handle = either onError return <=< tryIOError
