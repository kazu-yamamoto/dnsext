{-# LANGUAGE PatternSynonyms #-}

module DNS.Log (
    new,
    new',
    --
    Level (..),
    pattern DEMO,
    pattern WARN,
    pattern SYSTEM,
    --
    Output (..),
    Logger,
    PutLines,
    KillLogger,
) where

-- GHC packages
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad (when)
import Numeric.Natural
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

{- FOURMOLU_DISABLE -}
data Level
    = DEBUG
    | INFO
    | NOTICE
    | WARNING
    | ERR
    | CRIT     {- not used, syslog compat -}
    | ALERT    {- not used, syslog compat -}
    | EMERG    {- not used, syslog compat -}
    deriving (Eq, Ord, Show, Read)
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
{- levels for backword compat  -}
pattern DEMO     :: Level
pattern DEMO     = INFO
pattern WARN     :: Level
pattern WARN     = WARNING
pattern SYSTEM   :: Level
pattern SYSTEM   = ERR
{- FOURMOLU_ENABLE -}

data Output
    = Stdout
    | Stderr

instance Show Output where
    show Stdout = "Stdout"
    show Stderr = "Stderr"

type Logger = IO ()
type PutLines m = Level -> Maybe Color -> [String] -> m ()
type KillLogger = IO ()

new :: Output -> Level -> IO (Logger, PutLines IO, KillLogger)
new Stdout l = toIO $ newHandleLogger queueBound stdout l
new Stderr l = toIO $ newHandleLogger queueBound stderr l

new' :: Output -> Level -> IO (Logger, PutLines STM, KillLogger)
new' Stdout = newHandleLogger queueBound stdout
new' Stderr = newHandleLogger queueBound stderr

{- limit waiting area on server to constant size -}
queueBound :: Natural
queueBound = 8

toIO
    :: IO (Logger, PutLines STM, KillLogger)
    -> IO (Logger, PutLines IO, KillLogger)
toIO action = do
    (x, y, z) <- action
    return (x, (\l mc xs -> atomically $ y l mc xs), z)

newHandleLogger
    :: Natural -> Handle -> Level -> IO (Logger, PutLines STM, KillLogger)
newHandleLogger qsize outFh loggerLevel = do
    hSetBuffering outFh LineBuffering
    colorize <- hSupportsANSIColor outFh
    inQ <- newTBQueueIO qsize
    mvar <- newEmptyMVar
    let logger = loggerLoop inQ mvar
        put = putLines colorize inQ
        kill = killLogger inQ mvar
    return (logger, put, kill)
  where
    killLogger inQ mvar = do
        atomically $ writeTBQueue inQ $ \bk _ -> bk
        takeMVar mvar

    putLines colorize inQ lv color ~xs
        | colorize = withColor color
        | otherwise = withColor Nothing
      where
        withColor c =
            when (loggerLevel <= lv) $
                writeTBQueue inQ $
                    \_ ck -> ck c xs

    loggerLoop inQ mvar = loop
      where
        loop = do
            me <- atomically (readTBQueue inQ)
            me (putMVar mvar ()) $
                \c xs -> do
                    logit c xs
                    loop

    logit Nothing  xs = mapM_ (hPutStrLn outFh) xs
    logit (Just c) xs = do
        hSetSGR outFh [SetColor Foreground Vivid c]
        mapM_ (hPutStrLn outFh) xs
        hSetSGR outFh [Reset]
