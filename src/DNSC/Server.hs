{-# LANGUAGE ParallelListComp #-}

module DNSC.Server (
  run,

  bind, monitor,
  ) where

import Control.Monad ((<=<), when, unless)
import Data.Functor (($>))
import Data.Ord (Down (..))
import Data.List (uncons, isInfixOf)
import qualified Data.ByteString.Char8 as B8

import Network.Socket (AddrInfo (..), SocketType (Datagram), HostName, PortNumber, Socket, SockAddr)
import qualified Network.Socket as S
import Network.DNS (DNSMessage, DNSHeader, Question)
import qualified Network.DNS as DNS

import DNSC.Concurrent (forksConsumeQueueWith, forksLoopWith)
import DNSC.SocketUtil (mkSocketWaitForInput)
import DNSC.DNSUtil (recvFrom, sendTo)
import qualified DNSC.Log as Log
import DNSC.Iterative (Context (..), newContext, runReply)


type NE a = (a, [a])

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
  (cxt, quitCache) <- newContext putLines disableV6NS

  sas <- udpSockets port hosts

  let putLn lv = putLines lv . (:[])

  (enqueueResp, quitResp) <- forksConsumeQueueWith 1 (putLn Log.NOTICE . ("Server.sendResponse: " ++) . show) (sendResponse sendTo cxt)
  (enqueueReq, quitProc)  <- forksConsumeQueueWith para (putLn Log.NOTICE . ("Server.processRequest: " ++) . show) $ processRequest cxt enqueueResp

  waitInputs <- mapM (mkSocketWaitForInput . fst) sas
  quitReq <- forksLoopWith (putLn Log.NOTICE . ("Server.recvRequest: " ++) . show)
             [ recvRequest waitForInput recvFrom cxt enqueueReq sock
             | (sock, _) <- sas
             | waitForInput <- waitInputs
             ]

  mapM_ (uncurry S.bind) sas

  let quit = do
        quitReq
        quitProc
        quitResp
        quitCache
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

data Command
  = Find String
  | Lookup DNS.Domain DNS.TYPE
  | Size
  | Noop
  | Quit
  deriving Show

monitor :: Context -> IO () -> IO ()
monitor cxt quit = loop
  where
    parseTYPE "A"      = Just DNS.A
    parseTYPE "AAAA"   = Just DNS.AAAA
    parseTYPE "NS"     = Just DNS.NS
    parseTYPE "CNAME"  = Just DNS.CNAME
    parseTYPE _        = Nothing
    parseCmd []  =    Just Noop
    parseCmd ws  =  case ws of
      "find" : s : _      ->  Just $ Find s
      ["lookup", n, typ]  ->  Lookup (B8.pack n) <$> parseTYPE typ
      "size" : _  ->  Just Size
      "quit" : _  ->  Just Quit
      _           ->  Nothing

    runCmd Quit  =  quit $> True
    runCmd cmd   =  dispatch cmd $> False
      where
        dispatch Noop             =  return ()
        dispatch (Find s)         =  mapM_ putStrLn . filter (s `isInfixOf`) . map show =<< dump_ cxt
        dispatch (Lookup dom typ) =  maybe (putStrLn "miss.") hit =<< lookup_ cxt dom typ DNS.classIN
          where hit (rrs, Down rank) = mapM_ putStrLn $ ("hit: " ++ show rank) : map show rrs
        dispatch Size             =  print =<< size_ cxt
        dispatch x                =  putStrLn $ "command: unknown state: " ++ show x

    loop = do
      putStr "\nmonitor:\n"
      s <- getLine
      isQuit <- maybe (putStrLn "command: parse error" $> False) runCmd $ parseCmd $ words s
      unless isQuit loop
