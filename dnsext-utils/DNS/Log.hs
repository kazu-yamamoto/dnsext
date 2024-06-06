module DNS.Log (
    new,
    Level (..),
    Output (..),
    Logger,
    PutLines,
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
type KillLogger = IO ()

new :: Output -> Level -> IO (Logger, PutLines, KillLogger)
new Stdout = newHandleLogger stdout
new Stderr = newHandleLogger stderr

newHandleLogger
    :: Handle -> Level -> IO (Logger, PutLines, KillLogger)
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
                atomically $
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
