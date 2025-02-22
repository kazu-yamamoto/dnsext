{-# LANGUAGE PatternSynonyms #-}

module DNS.Log (
    new,
    new',
    with,
    fileWith,
    --
    Level (..),
    pattern DEMO,
    pattern WARN,
    pattern SYSTEM,
    --
    OutHandle (..),
    Logger,
    PutLines,
    KillLogger,
) where

-- GHC packages
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad (when)
import Data.Functor
import Numeric.Natural
import System.IO (
    BufferMode (LineBuffering),
    Handle,
    IOMode (AppendMode),
    hClose,
    hPutStrLn,
    hSetBuffering,
    openFile,
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

data OutHandle
    = Stdout
    | Stderr

instance Show OutHandle where
    show Stdout = "<stdout>"
    show Stderr = "<stderr>"

type Logger = IO ()
type PutLines m = Level -> Maybe Color -> [String] -> m ()
type KillLogger = IO ()
type ReopenLogger = IO ()

new :: OutHandle -> Level -> IO (Logger, PutLines IO, KillLogger)
new oh lv = with' oh (pure id) lv $ \lg _ p k _ -> pure (lg, p, k)

new' :: OutHandle -> Level -> IO (Logger, PutLines STM, KillLogger)
new' oh lv = with' oh (pure id) lv $ \lg p _ k _ -> pure (lg, p, k)

with :: OutHandle -> Level -> (Logger -> PutLines STM  -> KillLogger -> ReopenLogger -> IO a) -> IO a
with oh lv h = withHandleLogger queueBound (pure id) (pure $ handle oh) (\_ -> pure ()) lv $ \lg p _ k r -> h lg p k r

with'
    :: OutHandle -> IO ShowS -> Level
    -> (Logger -> PutLines STM -> PutLines IO -> KillLogger -> ReopenLogger -> IO a) -> IO a
with' oh getM = withHandleLogger queueBound getM (pure $ handle oh) (\_ -> pure ())

handle :: OutHandle -> Handle
handle Stdout = stdout
handle Stderr = stderr

fileWith :: FilePath -> Level -> (Logger -> PutLines STM  -> KillLogger -> ReopenLogger -> IO a) -> IO a
fileWith fn lv h = withHandleLogger queueBound (pure id) (openFile fn AppendMode) hClose lv $ \lg p _ k r -> h lg p k r

{- limit waiting area on server to constant size -}
queueBound :: Natural
queueBound = 8

{- FOURMOLU_DISABLE -}
withHandleLogger
    :: Natural -> IO ShowS -> IO Handle -> (Handle -> IO ())
    -> Level -> (Logger -> PutLines STM -> PutLines IO -> KillLogger -> ReopenLogger -> IO a) -> IO a
withHandleLogger qsize getM open close loggerLevel k = do
    outFh <- open'
    colorize  <- hSupportsANSIColor outFh
    inQ       <- newTBQueueIO qsize
    mvar      <- newEmptyMVar
    let logger  = loggerLoop inQ mvar outFh
        putSTM  = putLinesSTM colorize inQ
        putIO   = putLinesIO  colorize inQ
        kill    = killLogger inQ mvar
        reopen  = reopenLogger colorize inQ
    k logger putSTM putIO kill reopen
  where
    killLogger inQ mvar = do
        atomically                              $ writeTBQueue inQ $ \bk _  _  -> bk
        takeMVar mvar

    reopenLogger colorize inQ = do
        putLinesIO colorize inQ INFO Nothing ["re-opening log."]
        atomically                              $ writeTBQueue inQ $ \_  rk _  -> rk

    putLinesSTM  = putLines_ (pure id) id
    putLinesIO   = putLines_  getM     atomically

    putLines_ getM' toM colorize inQ lv ~color ~xs
        | colorize   = withColor color
        | otherwise  = withColor Nothing
      where
        withColor ~c = when (loggerLevel <= lv) $ do
            mdfy <- getM'
            toM                                 $ writeTBQueue inQ $ \_  _  ck -> ck c (map mdfy xs)

    loggerLoop inQ mvar = loop
      where
        loop outFh = do
            me <- atomically (readTBQueue inQ)
            let close'   = close outFh >> putMVar mvar ()
                reopen'  = close outFh >> open' >>= loop
            me close' reopen' $ \c xs -> logit outFh c xs >> loop outFh

    open' = open >>= \outFh -> hSetBuffering outFh LineBuffering $> outFh

    logit outFh Nothing  xs = mapM_ (hPutStrLn outFh) xs
    logit outFh (Just c) xs = do
        hSetSGR outFh [SetColor Foreground Vivid c]
        mapM_ (hPutStrLn outFh) xs
        hSetSGR outFh [Reset]
{- FOURMOLU_ENABLE -}
