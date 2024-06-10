module DNS.Log (
    new,
    new',
    Level (..),
    Output (..),
    Logger,
    PutLines,
    PutLinesSTM,
    KillLogger,
) where

-- GHC packages
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad (when)
import System.IO (
    BufferMode (LineBuffering),
    Handle,
    hPutStrLn,
    hSetBuffering,
    stderr,
    stdout,
 )

-- other packages
import System.Console.ANSI (hSetSGR, hSupportsANSIColor)
import System.Console.ANSI.Types

-- this package

data Level
    = DEBUG
    | DEMO
    | WARN
    | SYSTEM
    deriving (Eq, Ord, Show, Read)

data Output
    = Stdout
    | Stderr

instance Show Output where
    show Stdout = "Stdout"
    show Stderr = "Stderr"

type Logger = IO ()
type PutLines = Level -> Maybe Color -> [String] -> IO ()
type PutLinesSTM = Level -> Maybe Color -> [String] -> STM ()
type KillLogger = IO ()

new :: Output -> Level -> IO (Logger, PutLines, KillLogger)
new Stdout l = toIO $ newHandleLogger stdout l
new Stderr l = toIO $ newHandleLogger stderr l

new' :: Output -> Level -> IO (Logger, PutLinesSTM, KillLogger)
new' Stdout = newHandleLogger stdout
new' Stderr = newHandleLogger stderr

toIO
    :: IO (Logger, PutLinesSTM, KillLogger)
    -> IO (Logger, PutLines, KillLogger)
toIO action = do
    (x, y, z) <- action
    return (x, (\l mc xs -> atomically $ y l mc xs), z)

newHandleLogger
    :: Handle -> Level -> IO (Logger, PutLinesSTM, KillLogger)
newHandleLogger outFh loggerLevel = do
    hSetBuffering outFh LineBuffering
    colorize <- hSupportsANSIColor outFh
    inQ <- newTQueueIO
    mvar <- newEmptyMVar
    let logger = loggerLoop inQ mvar
        put = putLines colorize inQ
        kill = killLogger inQ mvar
    return (logger, put, kill)
  where
    killLogger inQ mvar = do
        atomically $ writeTQueue inQ Nothing
        takeMVar mvar

    putLines colorize inQ lv color ~xs
        | colorize = withColor color
        | otherwise = withColor Nothing
      where
        withColor c =
            when (loggerLevel <= lv) $
                writeTQueue inQ $
                    Just (c, xs)

    loggerLoop inQ mvar = loop
      where
        loop = do
            me <- atomically (readTQueue inQ)
            case me of
                Nothing -> putMVar mvar ()
                Just e -> do
                    logit e
                    loop

    logit (Nothing, xs) = mapM_ (hPutStrLn outFh) xs
    logit (Just c, xs) = do
        hSetSGR outFh [SetColor Foreground Vivid c]
        mapM_ (hPutStrLn outFh) xs
        hSetSGR outFh [Reset]
