module DNS.Cache.Log (
  Level (..),
  DemoFlag (..),
  Output (..),
  ThreadLoop,
  PutLines,
  GetQueueSize,
  Flush,
  newFastLogger,
  outputHandle,
  new,
  none,
  ) where

-- GHC packages
import Control.Concurrent.MVar (newEmptyMVar, takeMVar, putMVar)
import Control.Monad (forever, when)
import System.IO (Handle, hSetBuffering, BufferMode (LineBuffering), hPutStr, stdout, stderr)

-- other packages
import System.Console.ANSI (hSetSGR)
import System.Console.ANSI.Types
import System.Log.FastLogger (newStdoutLoggerSet, newStderrLoggerSet, pushLogStr, toLogStr, flushLogStr)
import UnliftIO (tryAny)

-- this package
import DNS.Cache.Queue (newQueue, readQueue, writeQueue)
import qualified DNS.Cache.Queue as Queue


data Level
  = DEMO  {- special level to specify demo output -}
  | DEBUG
  | INFO
  | NOTICE
  | WARN
  deriving (Eq, Ord, Show, Read)

data DemoFlag
  = DisableDemo
  | EnableDemo
  deriving (Eq, Show)

data Output
  = Stdout
  | Stderr
  deriving Show

type ThreadLoop = IO ()
type PutLines = Level -> Maybe Color -> [String] -> IO ()
type GetQueueSize = IO (Int, Int)
type Flush = IO ()

newFastLogger :: Output -> Level -> DemoFlag -> IO (PutLines, GetQueueSize, Flush)
newFastLogger out loggerLevel demoFlag = do
  loggerSet <- newLoggerSet bufsize
  let enabled lv = checkEnabledLevelWithDemo loggerLevel demoFlag lv
      logLines lv _ = when (enabled lv) . pushLogStr loggerSet . toLogStr . unlines
  return (logLines, return (-1, -1), flushLogStr loggerSet)
  where
    bufsize = 4096
    newLoggerSet = case out of
      Stdout  ->  newStdoutLoggerSet
      Stderr  ->  newStderrLoggerSet

outputHandle :: Output -> Handle
outputHandle o = case o of
  Stdout  ->  stdout
  Stderr  ->  stderr

new :: Handle -> Level -> DemoFlag -> IO (ThreadLoop, PutLines, GetQueueSize, Flush)
new outFh loggerLevel demoFlag = do
  hSetBuffering outFh LineBuffering

  inQ <- newQueue 8
  flushMutex <- newEmptyMVar
  let body = do
        let abody (color, xs) = do
              maybe (pure ()) (\c -> hSetSGR outFh [SetColor Foreground Vivid c]) $ color
              hPutStr outFh $ unlines xs
              maybe (pure ()) (const $ hSetSGR outFh [Reset]) $ color
            action  = maybe (putMVar flushMutex ()) abody
        either (const $ return ()) return =<< tryAny (action =<< readQueue inQ)
      enabled lv = checkEnabledLevelWithDemo loggerLevel demoFlag lv
      logLines lv color xs = when (enabled lv) $ writeQueue inQ $ Just (color, xs)
      flush = writeQueue inQ Nothing *> takeMVar flushMutex

  return (forever body, logLines, (,) <$> (fst <$> Queue.readSizes inQ) <*> pure (Queue.sizeMaxBound inQ), flush)

checkEnabledLevelWithDemo :: Level -> DemoFlag -> Level -> Bool
checkEnabledLevelWithDemo loggerLevel demoFlag lv = case demoFlag of
  DisableDemo  ->  loggerLevel <= lv
  EnableDemo   ->  lv == DEMO

-- no logging
none :: Level -> [String] -> IO ()
none _ _ = return ()
