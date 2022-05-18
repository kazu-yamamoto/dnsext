module DNSC.Log (
  Level (..),
  FOutput (..),
  newFastLogger,
  new,
  none,
  ) where

-- GHC packages
import Control.Monad (when)
import System.IO (Handle, hSetBuffering, BufferMode (LineBuffering), hPutStr)

-- other packages
import System.Log.FastLogger (newStdoutLoggerSet, newStderrLoggerSet, pushLogStr, toLogStr, flushLogStr)

-- this package
import DNSC.Concurrent (forkConsumeQueue)


data Level
  = DEBUG
  | INFO
  | NOTICE
  | WARN
  deriving (Eq, Ord, Show, Read)

data FOutput
  = FStdout
  | FStderr
  deriving Show

newFastLogger :: FOutput -> Level -> IO (Level -> [String] -> IO (), IO (Int, Int), IO ())
newFastLogger out level = do
  loggerSet <- newLoggerSet bufsize
  let logLines lv = when (level <= lv) . pushLogStr loggerSet . toLogStr . unlines
  return (logLines, return (-1, -1), flushLogStr loggerSet)
  where
    bufsize = 4096
    newLoggerSet = case out of
      FStdout  ->  newStdoutLoggerSet
      FStderr  ->  newStderrLoggerSet

new :: Handle -> Level -> IO (Level -> [String] -> IO (), IO (Int, Int), IO ())
new outFh level = do
  hSetBuffering outFh LineBuffering

  (enqueue, readSize, quit) <- forkConsumeQueue $ hPutStr outFh . unlines
  let logLines lv = when (level <= lv) . enqueue

  return (logLines, readSize, quit)

-- no logging
none :: Level -> [String] -> IO ()
none _ _ = return ()
