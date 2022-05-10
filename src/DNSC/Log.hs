module DNSC.Log (
  Level (..),
  new,
  none,
  ) where

-- GHC packages
import Control.Monad (when)
import System.IO (Handle, hSetBuffering, BufferMode (LineBuffering), hPutStr)

-- this package
import DNSC.Concurrent (forkConsumeQueue)


data Level
  = DEBUG
  | INFO
  | NOTICE
  | WARN
  deriving (Eq, Ord, Show, Read)

new :: Handle -> Level -> IO (Level -> [String] -> IO (), IO ())
new outFh level = do
  hSetBuffering outFh LineBuffering

  (enqueue, quit) <- forkConsumeQueue $ hPutStr outFh . unlines
  let logLines lv = when (level <= lv) . enqueue

  return (logLines, quit)

-- no logging
none :: Level -> [String] -> IO ()
none _ _ = return ()
