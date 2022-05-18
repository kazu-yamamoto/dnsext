
module DNSC.ServerMonitor where

-- GHC internal packages
import GHC.IO.Device (ready)
import GHC.IO.Handle.Internals (wantReadableHandle_)
import GHC.IO.Handle.Types (Handle__ (..))

-- GHC packages
import Control.Monad ((<=<), when, unless, void)
import Data.Functor (($>))
import Data.List (isInfixOf, find)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.Char (toUpper)
import qualified Data.ByteString.Char8 as B8
import System.IO (IOMode (ReadWriteMode), Handle, hGetLine, hIsEOF, hPutStr, hPutStrLn, hFlush, hClose, stdin, stdout)
import System.IO.Error (tryIOError)

-- dns packages
import Control.Concurrent.Async (async, wait)
import Network.Socket (AddrInfo (..), SocketType (Stream), HostName, PortNumber, Socket, SockAddr)
import qualified Network.Socket as S
import qualified Network.DNS as DNS

-- this package
import DNSC.SocketUtil (addrInfo, mkSocketWaitForByte)
import qualified DNSC.Log as Log
import DNSC.Iterative (Context (..))


monitorSockets :: PortNumber -> [HostName] -> IO [(Socket, SockAddr)]
monitorSockets port = mapM aiSocket . filter ((== Stream) . addrSocketType) <=< addrInfo port
  where
    aiSocket ai = (,) <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai) <*> pure (addrAddress ai)

data Command
  = Find String
  | Lookup DNS.Domain DNS.TYPE
  | Status
  | Noop
  | Exit
  | Quit
  deriving Show

monitor :: Bool -> Context
        -> (IO (Int, Int), IO (Int, Int), IO (Int, Int), IO (Int, Int))
        -> IO () -> IO ()
monitor stdConsole cxt getsSizeInfo quit = do
  ps <- monitorSockets 10023 ["::1", "127.0.0.1"]
  let ss = map fst ps
  sequence_ [ S.setSocketOption sock S.ReuseAddr 1 | sock <- ss ]
  mapM_ (uncurry S.bind) ps
  sequence_ [ S.listen sock 5 | sock <- ss ]
  monQuitRef <- newIORef False
  when stdConsole $ runStdConsole monQuitRef
  mas <- mapM (getMonitor monQuitRef) ss
  ms <- mapM async mas
  mapM_ wait ms
  where
    runStdConsole monQuitRef = do
      repl <- getConsole cxt getsSizeInfo quit monQuitRef stdin stdout "<std>"
      void $ async repl
    logLn level = logLines_ cxt level . (:[])
    handle onError = either onError return <=< tryIOError
    getMonitor monQuitRef s = do
      waitForInput <- mkSocketWaitForByte s
      let step = do
            hasInput <- waitForInput $ 1 * 1000
            when hasInput $ do
              (sock, addr) <- S.accept s
              sockh <- S.socketToHandle sock ReadWriteMode
              repl <- getConsole cxt getsSizeInfo quit monQuitRef sockh sockh $ show addr
              void $ async $ repl *> hClose sockh
          loop = do
            isQuit <- readIORef monQuitRef
            unless isQuit $ do
              handle (logLn Log.NOTICE . ("monitor io-error: " ++) . show) step
              loop
      return loop

getConsole :: Context -> (IO (Int, Int), IO (Int, Int), IO (Int, Int), IO (Int, Int))
           -> IO () -> IORef Bool -> Handle -> Handle -> String -> IO (IO ())
getConsole cxt (reqQSize, resQSize, ucacheQSize, logQSize) quit monQuitRef inH outH ainfo = do
  let prompt = hPutStr outH "monitor> " *> hFlush outH
      input = do
        s <- hGetLine inH
        let err = hPutStrLn outH ("monitor error: " ++ ainfo ++ ": command parse error: " ++ show s)
            run_ = runCmd (writeIORef monQuitRef True)
        exit <- maybe (err $> False) run_ $ parseCmd $ words s
        unless exit prompt
        return exit

      step = do
        hasInput <- hWaitForByte inH $ 1 * 1000
        if hasInput
          then do eof <- hIsEOF inH
                  if eof then return True else input
          else return False

      repl = do
        isQuit <- readIORef monQuitRef
        unless isQuit $ do
          exit <- handle (($> False) . print) step
          unless exit repl

  return (prompt *> repl)

  where
    handle onError = either onError return <=< tryIOError

    parseTYPE s =
      find match types
      where
        us = map toUpper s
        match t = show t == us
        types = map DNS.toTYPE [1..512]

    parseCmd []  =    Just Noop
    parseCmd ws  =  case ws of
      "find" : s : _      ->  Just $ Find s
      ["lookup", n, typ]  ->  Lookup (B8.pack n) <$> parseTYPE typ
      "status" : _  ->  Just Status
      "exit" : _  ->  Just Exit
      "quit" : _  ->  Just Quit
      _           ->  Nothing

    runCmd monIssueQuit Quit  =  quit *> monIssueQuit $> True
    runCmd _            Exit  =  return True
    runCmd _            cmd   =  dispatch cmd $> False
      where
        outLn = hPutStrLn outH
        dispatch Noop             =  return ()
        dispatch (Find s)         =  mapM_ outLn . filter (s `isInfixOf`) . map show =<< dump_ cxt
        dispatch (Lookup dom typ) =  maybe (outLn "miss.") hit =<< lookup_ cxt dom typ DNS.classIN
          where hit (rrs, rank) = mapM_ outLn $ ("hit: " ++ show rank) : map show rrs
        dispatch Status           =  printStatus
        dispatch x                =  outLn $ "command: unknown state: " ++ show x

    printStatus = do
      let outLn = hPutStrLn outH
      outLn . ("cache size: " ++) . show =<< size_ cxt
      let psize s getSize = do
            (cur, mx) <- getSize
            outLn $ s ++ " size: " ++ show cur ++ " / " ++ show mx
      psize "request queue" reqQSize
      psize "response queue" resQSize
      psize "ucache queue" ucacheQSize
      lmx <- snd <$> logQSize
      when (lmx >= 0) $ psize "log queue" logQSize


hWaitForByte :: Handle -> Int -> IO Bool
hWaitForByte h msecs =
  wantReadableHandle_ "hWaitForByte" h $
  \ Handle__{ haDevice = haDev } -> ready haDev False{-read-} msecs
