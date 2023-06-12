module DNS.Log (
    new,
    Output (..),
    FileLogSpec (..),
    BufSize,
    PutLines,
    GetQueueSize,
    Terminate,
    Level (..),
    DemoFlag (..),
) where

-- GHC packages
import Control.Concurrent (forkIO, killThread)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Monad (forever, when)
import System.IO (
    BufferMode (LineBuffering),
    Handle,
    hPutStr,
    hSetBuffering,
    stderr,
    stdout,
 )

-- other packages
import System.Console.ANSI (hSetSGR)
import System.Console.ANSI.Types
import System.Log.FastLogger (
    BufSize,
    FileLogSpec (..),
    LogType,
    LogType' (..),
    newFastLogger1,
    toLogStr,
 )
import UnliftIO (tryAny)

-- this package
import DNS.Queue (newQueue, readQueue, writeQueue)
import qualified DNS.Queue as Queue

data Level
    = DEMO {- special level to specify demo output -}
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
    | RouteFile FileLogSpec BufSize

type PutLines = Level -> Maybe Color -> [String] -> IO ()
type GetQueueSize = IO (Int, Int)
type Terminate = IO ()

new :: Output -> Level -> DemoFlag -> IO (PutLines, GetQueueSize, Terminate)
new Stdout = newHandleLogger stdout
new Stderr = newHandleLogger stderr
new (RouteFile fs sz) = newFileLogger $ LogFile fs sz

newFileLogger
    :: LogType -> Level -> DemoFlag -> IO (PutLines, GetQueueSize, Terminate)
newFileLogger lt loggerLevel demoFlag = do
    (put, kill) <- newFastLogger1 lt
    return (logLines put, getQSize, kill)
  where
    logLines put lv _ xs =
        when (enabled lv) $
            put $
                toLogStr $
                    unlines xs
    enabled lv = checkEnabledLevelWithDemo loggerLevel demoFlag lv

    getQSize = return (-1, -1)

newHandleLogger
    :: Handle -> Level -> DemoFlag -> IO (PutLines, GetQueueSize, Terminate)
newHandleLogger outFh loggerLevel demoFlag = do
    hSetBuffering outFh LineBuffering
    inQ <- newQueue 8
    flushMutex <- newEmptyMVar
    tid <- forkIO $ logLoop inQ flushMutex
    return (logLines inQ, getQSize inQ, kill inQ flushMutex tid)
  where
    logLines inQ lv color xs =
        when (enabled lv) $
            writeQueue inQ $
                Just (color, xs)
    enabled lv = checkEnabledLevelWithDemo loggerLevel demoFlag lv

    getQSize inQ = do
        s <- fst <$> Queue.readSizes inQ
        let m = Queue.sizeMaxBound inQ
        return (s, m)

    kill inQ flushMutex tid = do
        () <- writeQueue inQ Nothing >> takeMVar flushMutex
        killThread tid

    logLoop inQ flushMutex = forever $ do
        _ex <- tryAny (readQueue inQ >>= logit flushMutex)
        return ()
    logit flushMutex mx = case mx of
        Nothing -> putMVar flushMutex ()
        Just x -> case x of
            (Nothing, xs) -> do
                hPutStr outFh $ unlines xs
            (Just c, xs) -> do
                hSetSGR outFh [SetColor Foreground Vivid c]
                hPutStr outFh $ unlines xs
                hSetSGR outFh [Reset]

checkEnabledLevelWithDemo :: Level -> DemoFlag -> Level -> Bool
checkEnabledLevelWithDemo loggerLevel demoFlag lv = case demoFlag of
    DisableDemo -> loggerLevel <= lv
    EnableDemo -> lv == DEMO
