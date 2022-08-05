
module DNSC.ServerMonitor (
  monitor,
  Params,
  makeParams,
  showParams,
  PLStatus,
  ) where

-- GHC packages
import Control.Applicative ((<|>))
import Control.Concurrent (forkIO, forkFinally, threadWaitRead)
import Control.Concurrent.STM (STM, atomically, newTVarIO, readTVar, writeTVar)
import Control.Monad ((<=<), guard, when, unless, void)
import Data.Functor (($>))
import Data.List (isInfixOf, find)
import Data.Char (toUpper)
import Data.Int (Int64)
import qualified Data.ByteString.Char8 as B8
import Text.Read (readMaybe)
import System.IO (IOMode (ReadWriteMode), Handle, hGetLine, hIsEOF, hPutStr, hPutStrLn, hFlush, hClose, stdin, stdout)

-- dns packages
import Network.Socket (AddrInfo (..), SocketType (Stream), HostName, PortNumber, Socket, SockAddr)
import qualified Network.Socket as S
import qualified Network.DNS as DNS

-- other packages
import UnliftIO (tryAny, waitSTM, withAsync)

-- this package
import qualified DNSC.DNSUtil as Config
import DNSC.SocketUtil (addrInfo)
import qualified DNSC.Log as Log
import qualified DNSC.Cache as Cache
import DNSC.Iterative (Context (..))


data Params =
  Params
  { isRecvSendMsg :: Bool
  , isExtendedLookup :: Bool
  , numCapabilities :: Int
  , logOutput :: Log.Output
  , logLevel :: Log.Level
  , maxCacheSize :: Int
  , disableV6NS :: Bool
  , workersPerSocket :: Int
  , queueSizePerWorker :: Int
  , dnsPort :: PortNumber
  , monitorPort :: PortNumber
  , dnsHosts :: [String]
  }

makeParams :: Int -> Log.Output -> Log.Level -> Int -> Bool -> Int -> Int -> PortNumber -> [String]
           -> Params
makeParams capabilities output level maxSize disableV6 workers perWorker port hosts =
  Params
  { isRecvSendMsg = Config.isRecvSendMsg
  , isExtendedLookup = Config.isExtendedLookup
  , numCapabilities = capabilities
  , logOutput = output
  , logLevel = level
  , maxCacheSize = maxSize
  , disableV6NS = disableV6
  , workersPerSocket = workers
  , queueSizePerWorker = perWorker
  , dnsPort = port
  , monitorPort = port + 9970
  , dnsHosts = hosts
  }

showParams :: Params -> [String]
showParams params =
  [ field  "recvmsg / sendmsg" isRecvSendMsg
  , field  "extended lookup" isExtendedLookup
  , field  "capabilities" numCapabilities
  , field_ "log output" (showOut . logOutput)
  , field  "log level" logLevel
  , field  "max cache size" maxCacheSize
  , field  "disable queries to IPv6 NS" disableV6NS
  , field  "worker threads per socket" workersPerSocket
  , field  "queue size per worker" queueSizePerWorker
  , field  "DNS port" dnsPort
  , field  "Monitor port" monitorPort
  ] ++
  if null hosts
  then ["DNS host list: null"]
  else  "DNS host list:" : map ("DNS host: " ++) hosts
  where
    field_ label toS = label ++ ": " ++ toS params
    field label get = field_ label (show . get)
    showOut Log.Stdout = "stdout"
    showOut Log.Stderr = "stderr"
    hosts = dnsHosts params

type PLStatus = [(IO (Int, Int), IO (Int, Int), IO (Int, Int), IO Int, IO Int, IO Int)]

monitorSockets :: PortNumber -> [HostName] -> IO [(Socket, SockAddr)]
monitorSockets port = mapM aiSocket . filter ((== Stream) . addrSocketType) <=< addrInfo port
  where
    aiSocket ai = (,) <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai) <*> pure (addrAddress ai)

data Command
  = Param
  | Find String
  | Lookup DNS.Domain DNS.TYPE
  | Status
  | Expire Int64
  | Noop
  | Exit
  | Quit
  deriving Show

monitor :: Bool -> Params -> Context
        -> ([PLStatus], IO (Int, Int), IO (Int, Int))
        -> (Int64 -> IO ()) -> IO () -> IO [IO ()]
monitor stdConsole params cxt getsSizeInfo expires flushLog = do
  ps <- monitorSockets (monitorPort params) ["::1", "127.0.0.1"]
  let ss = map fst ps
  sequence_ [ S.setSocketOption sock S.ReuseAddr 1 | sock <- ss ]
  mapM_ (uncurry S.bind) ps
  sequence_ [ S.listen sock 5 | sock <- ss ]
  monQuit <- do
    qRef <- newTVarIO False
    return (writeTVar qRef True, readTVar qRef >>= guard)
  when stdConsole $ runStdConsole monQuit
  return $ map (monitorServer monQuit) ss
  where
    runStdConsole monQuit = do
      let repl = console params cxt getsSizeInfo expires flushLog monQuit stdin stdout "<std>"
      void $ forkIO repl
    logLn level = logLines_ cxt level . (:[])
    handle onError = either onError return <=< tryAny
    monitorServer monQuit@(_, waitQuit) s = do
      let step = do
            socketWaitRead s
            (sock, addr) <- S.accept s
            sockh <- S.socketToHandle sock ReadWriteMode
            let repl = console params cxt getsSizeInfo expires flushLog monQuit sockh sockh $ show addr
            void $ forkFinally repl (\_ -> hClose sockh)
          loop =
            either (const $ return ()) (const loop)
            =<< withWait waitQuit (handle (logLn Log.NOTICE . ("monitor io-error: " ++) . show) step)
      loop

console :: Params -> Context -> ([PLStatus], IO (Int, Int), IO (Int, Int))
           -> (Int64 -> IO ()) -> IO () -> (STM (), STM ()) -> Handle -> Handle -> String -> IO ()
console params cxt (pQSizeList, ucacheQSize, logQSize) expires flushLog (issueQuit, waitQuit) inH outH ainfo = do
  let input = do
        s <- hGetLine inH
        let err = hPutStrLn outH ("monitor error: " ++ ainfo ++ ": command parse error: " ++ show s)
        maybe (err $> False) runCmd $ parseCmd $ words s

      step = do
        eof <- hIsEOF inH
        if eof then return True else input

      repl = do
        hPutStr outH "monitor> " *> hFlush outH
        either
          (const $ return ())
          (\exit -> unless exit repl)
          =<< withWait waitQuit (handle (($> False) . print) step)

  repl

  where
    handle onError = either onError return <=< tryAny

    parseTYPE s =
      find match types
      where
        us = map toUpper s
        match t = show t == us
        types = map DNS.toTYPE [1..512]

    parseCmd []  =    Just Noop
    parseCmd ws  =  case ws of
      "param" : _ ->  Just Param
      "find" : s : _      ->  Just $ Find s
      ["lookup", n, typ]  ->  Lookup (B8.pack n) <$> parseTYPE typ
      "status" : _  ->  Just Status
      "expire" : args -> case args of
        []     ->  Just $ Expire 0
        x : _  ->  Expire <$> readMaybe x
      "exit" : _  ->  Just Exit
      "quit" : _  ->  Just Quit
      _           ->  Nothing

    runCmd Quit  =  flushLog *> atomically issueQuit $> True
    runCmd Exit  =  return True
    runCmd cmd   =  dispatch cmd $> False
      where
        outLn = hPutStrLn outH
        dispatch Param            =  mapM_ outLn $ showParams params
        dispatch Noop             =  return ()
        dispatch (Find s)         =  mapM_ outLn . filter (s `isInfixOf`) . map show . Cache.dump =<< getCache_ cxt
        dispatch (Lookup dom typ) =  maybe (outLn "miss.") hit =<< lookupCache
          where lookupCache = do
                  cache <- getCache_ cxt
                  ts <- currentSeconds_ cxt
                  return $ Cache.lookup ts dom typ DNS.classIN cache
                hit (rrs, rank) = mapM_ outLn $ ("hit: " ++ show rank) : map show rrs
        dispatch Status           =  printStatus
        dispatch (Expire offset)  =  expires . (+ offset) =<< currentSeconds_ cxt
        dispatch x                =  outLn $ "command: unknown state: " ++ show x

    printStatus = do
      let outLn = hPutStrLn outH
      outLn . ("cache size: " ++) . show . Cache.size =<< getCache_ cxt
      let psize s getSize = do
            (cur, mx) <- getSize
            outLn $ s ++ " size: " ++ show cur ++ " / " ++ show mx
      sequence_
        [ do psize ("request queue " ++ index) reqQSize
             psize ("decoded queue " ++ index) decQSize
             psize ("response queue " ++ index) resQSize
        | (i, workerStatusList) <- zip [0 :: Int ..] pQSizeList
        , (j, (reqQSize, decQSize, resQSize, _, _, _)) <- zip [0 :: Int ..] workerStatusList
        , let index = show i ++ "," ++ show j
        ]
      psize "ucache queue" ucacheQSize
      lmx <- snd <$> logQSize
      when (lmx >= 0) $ psize "log queue" logQSize

      ts <- sequence
        [ (,,) <$> getHit <*> getMiss <*> getFailed
        | workerStatusList <- pQSizeList
        , (_, _, _, getHit, getMiss, getFailed) <- workerStatusList ]
      let hits = sum [ hit | (hit, _, _) <- ts ]
          replies = hits + sum [ miss | (_, miss, _) <- ts ]
          total = replies + sum [ failed | (_, _, failed) <- ts ]
      outLn $ "hit rate: " ++ show hits ++ " / " ++ show replies
      outLn $ "reply rate: " ++ show replies ++ " / " ++ show total


withWait :: STM a -> IO b -> IO (Either a b)
withWait qstm blockAct =
  withAsync blockAct $ \a ->
  atomically $
    (Left  <$> qstm)
    <|>
    (Right <$> waitSTM a)

socketWaitRead :: Socket -> IO ()
socketWaitRead sock = S.withFdSocket sock $ threadWaitRead . fromIntegral
