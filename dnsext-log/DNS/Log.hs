module DNS.Log (
    new,
    Level (..),
    Output (..),
    PutLines,
) where

-- GHC packages
import Control.Monad (forever, void, when)
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
import qualified UnliftIO.Exception as E
import UnliftIO.STM

-- this package

data Level
    = DEBUG
    | DEMO
    | WARN
    deriving (Eq, Ord, Show, Read)

data Output
    = Stdout
    | Stderr

instance Show Output where
    show Stdout = "Stdout"
    show Stderr = "Stderr"

type PutLines = Level -> Maybe Color -> [String] -> IO ()

new :: Output -> Level -> IO (IO (), PutLines, IO ())
new Stdout = newHandleLogger stdout
new Stderr = newHandleLogger stderr

newHandleLogger
    :: Handle -> Level -> IO (IO (), PutLines, IO ())
newHandleLogger outFh loggerLevel = do
    hSetBuffering outFh LineBuffering
    colorize <- hSupportsANSIColor outFh
    inQ <- newTQueueIO
    let logger = logLoop inQ
        put = logLines colorize inQ
    return (logger, put, flush inQ)
  where
    logLines colorize inQ lv color ~xs
        | colorize = withColor color
        | otherwise = withColor Nothing
      where
        withColor c =
            when (loggerLevel <= lv) $
                atomically $
                    writeTQueue inQ (c, xs)

    logLoop inQ = forever write
      where
        write = void $ E.tryAny (atomically (readTQueue inQ) >>= logit)

    flush inQ = do
        mx <- atomically $ tryReadTQueue inQ
        case mx of
            Nothing -> return ()
            Just x -> do
                logit x
                flush inQ

    logit (Nothing, xs) = hPutStr outFh $ unlines xs
    logit (Just c, xs) = do
        hSetSGR outFh [SetColor Foreground Vivid c]
        hPutStr outFh $ unlines xs
        hSetSGR outFh [Reset]
