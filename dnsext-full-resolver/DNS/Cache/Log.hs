module DNS.Cache.Log (
  Level (..),
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
import System.Log.FastLogger (newStdoutLoggerSet, newStderrLoggerSet, pushLogStr, toLogStr, flushLogStr)
import UnliftIO (tryAny)

-- this package
import DNS.Cache.Queue (newQueue, readQueue, writeQueue)
import qualified DNS.Cache.Queue as Queue


data Level
  = DEBUG
  | INFO
  | NOTICE
  | WARN
  deriving (Eq, Ord, Show, Read)

data Output
  = Stdout
  | Stderr
  deriving Show

type ThreadLoop = IO ()
type PutLines = Level -> [String] -> IO ()
type GetQueueSize = IO (Int, Int)
type Flush = IO ()

newFastLogger :: Output -> Level -> IO (PutLines, GetQueueSize, Flush)
newFastLogger out level = do
  loggerSet <- newLoggerSet bufsize
  let logLines lv = when (level <= lv) . pushLogStr loggerSet . toLogStr . unlines
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

new :: Handle -> Level -> IO (ThreadLoop, PutLines, GetQueueSize, Flush)
new outFh level = do
  hSetBuffering outFh LineBuffering

  inQ <- newQueue 8
  flushMutex <- newEmptyMVar
  let body = do
        let action = maybe (putMVar flushMutex ()) (hPutStr outFh . unlines)
        either (const $ return ()) return =<< tryAny (action =<< readQueue inQ)
      logLines lv = when (level <= lv) . writeQueue inQ . Just
      flush = writeQueue inQ Nothing *> takeMVar flushMutex

  return (forever body, logLines, (,) <$> (fst <$> Queue.readSizes inQ) <*> pure (Queue.sizeMaxBound inQ), flush)

-- no logging
none :: Level -> [String] -> IO ()
none _ _ = return ()
