module DNSC.Log (
  Level (..),
  Output (..),
  newFastLogger,
  outputHandle,
  new,
  none,
  ) where

-- GHC packages
import Control.Monad (forever, when)
import System.IO (Handle, hSetBuffering, BufferMode (LineBuffering), hPutStr, stdout, stderr)

-- other packages
import System.Log.FastLogger (newStdoutLoggerSet, newStderrLoggerSet, pushLogStr, toLogStr, flushLogStr)
import UnliftIO (tryAny)

-- this package
import DNSC.Queue (newQueue, readQueue, writeQueue)
import qualified DNSC.Queue as Queue


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

newFastLogger :: Output -> Level -> IO (Level -> [String] -> IO (), IO (Int, Int), IO ())
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

new :: Handle -> Level -> IO (IO (), Level -> [String] -> IO (), IO (Int, Int))
new outFh level = do
  hSetBuffering outFh LineBuffering

  inQ <- newQueue 8
  let body = either (const $ return ()) return =<< tryAny (hPutStr outFh . unlines =<< readQueue inQ)
      logLines lv = when (level <= lv) . writeQueue inQ

  return (forever body, logLines, (,) <$> Queue.readSize inQ <*> pure (Queue.maxSize inQ))

-- no logging
none :: Level -> [String] -> IO ()
none _ _ = return ()
