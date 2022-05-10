{-# LANGUAGE ParallelListComp #-}

module DNSC.Server (
  run,

  bind, monitor,
  ) where

-- GHC packages
import Control.Monad ((<=<), when)
import Data.List (uncons)

-- dns packages
import Network.Socket (AddrInfo (..), SocketType (Datagram), HostName, PortNumber, Socket, SockAddr)
import qualified Network.Socket as S
import Network.DNS (DNSMessage, DNSHeader, Question)
import qualified Network.DNS as DNS

-- this package
import DNSC.Concurrent (forksConsumeQueueWith, forksLoopWith)
import DNSC.SocketUtil (mkSocketWaitForInput, isAnySockAddr)
import DNSC.DNSUtil (mkRecv, mkSend)
import DNSC.ServerMonitor (monitor)
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

addrInfo :: PortNumber -> [HostName] -> IO [AddrInfo]
addrInfo p []        = S.getAddrInfo Nothing Nothing $ Just $ show p
addrInfo p hs@(_:_)  = concat <$> sequence [ S.getAddrInfo Nothing (Just h) $ Just $ show p | h <- hs ]

run :: Log.Level -> Bool -> Int
    -> PortNumber -> [HostName] -> IO ()
run level disableV6NS conc port hosts =
  uncurry monitor =<< bind level disableV6NS conc port hosts

bind :: Log.Level -> Bool -> Int
     -> PortNumber -> [HostName]
     -> IO (Context, IO ())
bind level disableV6NS para port hosts = do
  (putLines, quitLog) <- Log.new level
  (tcache@(getSec, _), quitTimeCache) <- TimeCache.new
  (ucache, quitCache) <- UCache.new putLines tcache
  cxt <- newContext putLines disableV6NS ucache tcache

  sas <- udpSockets port hosts

  let putLn lv = putLines lv . (:[])
      send sock msg (peer, cmsgs, wildcard) = mkSend wildcard sock msg peer cmsgs

  (enqueueResp, quitResp) <- forksConsumeQueueWith 1 (putLn Log.NOTICE . ("Server.sendResponse: " ++) . show) (sendResponse send cxt)
  (enqueueReq, quitProc)  <- forksConsumeQueueWith para (putLn Log.NOTICE . ("Server.processRequest: " ++) . show) $ processRequest cxt enqueueResp

  waitInputs <- mapM (mkSocketWaitForInput . fst) sas
  quitReq <- forksLoopWith (putLn Log.NOTICE . ("Server.recvRequest: " ++) . show)
             [ recvRequest waitForInput recv cxt enqueueReq sock
             | (sock, addr) <- sas
             , let wildcard = isAnySockAddr addr
                   recv s = do
                     now <- getSec
                     mkRecv wildcard now s
             | waitForInput <- waitInputs
             ]

  mapM_ (uncurry S.bind) sas

  let quit = do
        quitReq
        quitProc
        quitResp
        quitCache
        quitTimeCache
        quitLog

  return (cxt, quit)

recvRequest :: Show a
            => (Int -> IO Bool)
            -> (s -> IO (DNSMessage, a))
            -> Context
            -> (Request s a -> IO ())
            -> s
            -> IO ()
recvRequest waitInput recv cxt enqReq sock = do
  hasInput <- waitInput (3 * 1000)
  when hasInput $ do
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
