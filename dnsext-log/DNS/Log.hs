module DNS.Log (
    new,
    Output (..),
    FileLogSpec (..),
    BufSize,
    PutLines,
    GetQueueSize,
    Terminate,
    Level (..),
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
import System.Console.ANSI (hSetSGR, hSupportsANSIColor)
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
    = DEBUG
    | DEMO
    | WARN
    deriving (Eq, Ord, Show, Read)

data Output
    = Stdout
    | Stderr
    | RouteFile FileLogSpec BufSize

type PutLines = Level -> Maybe Color -> [String] -> IO ()
type GetQueueSize = IO (Int, Int)
type Terminate = IO ()

new :: Output -> Level -> IO (PutLines, GetQueueSize, Terminate)
new Stdout = newHandleLogger stdout
new Stderr = newHandleLogger stderr
new (RouteFile fs sz) = newFileLogger $ LogFile fs sz

newFileLogger
    :: LogType -> Level -> IO (PutLines, GetQueueSize, Terminate)
newFileLogger lt loggerLevel = do
    (put, kill) <- newFastLogger1 lt
    return (logLines put, getQSize, kill)
  where
    logLines put lv _ xs =
        when (loggerLevel <= lv) $
            put $
                toLogStr $
                    unlines xs

    getQSize = return (-1, -1)

newHandleLogger
    :: Handle -> Level -> IO (PutLines, GetQueueSize, Terminate)
newHandleLogger outFh loggerLevel = do
    hSetBuffering outFh LineBuffering
    colorize <- hSupportsANSIColor outFh
    inQ <- newQueue 8
    flushMutex <- newEmptyMVar
    tid <- forkIO $ logLoop inQ flushMutex
    return (logLines colorize inQ, getQSize inQ, kill inQ flushMutex tid)
  where
    logLines colorize inQ lv color xs
        | colorize = withColor color
        | otherwise = withColor Nothing
      where
        withColor c = when (loggerLevel <= lv) $ writeQueue inQ $ Just (c, xs)

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
