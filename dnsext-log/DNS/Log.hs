module DNS.Log (
  Level (..),
  DemoFlag (..),
  Output (..),
  ThreadLoop,
  PutLines,
  GetQueueSize,
  Flush,
  newFastLogger,
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
import System.Log.FastLogger (newStdoutLoggerSetN, newStderrLoggerSetN, pushLogStr, toLogStr, flushLogStr)
import UnliftIO (tryAny)

-- this package
import DNS.Queue (newQueue, readQueue, writeQueue)
import qualified DNS.Queue as Queue


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
  loggerSet <- newLoggerSetN bufsize $ Just 1
  let enabled lv = checkEnabledLevelWithDemo loggerLevel demoFlag lv
      logLines lv _ = when (enabled lv) . pushLogStr loggerSet . toLogStr . unlines
  return (logLines, return (-1, -1), flushLogStr loggerSet)
  where
    bufsize = 4096
    newLoggerSetN = case out of
      Stdout  ->  newStdoutLoggerSetN
      Stderr  ->  newStderrLoggerSetN

outputHandle :: Output -> Handle
outputHandle o = case o of
  Stdout  ->  stdout
  Stderr  ->  stderr

new :: Output -> Level -> DemoFlag -> IO (ThreadLoop, PutLines, GetQueueSize, Flush)
new out loggerLevel demoFlag = do
    hSetBuffering outFh LineBuffering
    inQ <- newQueue 8
    flushMutex <- newEmptyMVar
    return ( logLoop inQ flushMutex
           , logLines inQ
           , getQSize inQ
           , flush inQ flushMutex)
  where
    outFh = outputHandle out
    flush inQ flushMutex = writeQueue inQ Nothing >> takeMVar flushMutex

    logLines inQ lv color xs = when (enabled lv) $
        writeQueue inQ $ Just (color, xs)
    enabled lv = checkEnabledLevelWithDemo loggerLevel demoFlag lv

    getQSize inQ = do
        s <- fst <$> Queue.readSizes inQ
        let m = Queue.sizeMaxBound inQ
        return (s,m)

    logLoop inQ flushMutex = forever $ do
        _ex <- tryAny (readQueue inQ >>= logit flushMutex)
        return ()
    logit flushMutex mx = case mx of
      Nothing -> putMVar flushMutex ()
      Just x  -> case x of
        (Nothing, xs) -> do
            hPutStr outFh $ unlines xs
        (Just c, xs)  -> do
            hSetSGR outFh [SetColor Foreground Vivid c]
            hPutStr outFh $ unlines xs
            hSetSGR outFh [Reset]

checkEnabledLevelWithDemo :: Level -> DemoFlag -> Level -> Bool
checkEnabledLevelWithDemo loggerLevel demoFlag lv = case demoFlag of
  DisableDemo  ->  loggerLevel <= lv
  EnableDemo   ->  lv == DEMO

-- no logging
none :: Level -> [String] -> IO ()
none _ _ = return ()
