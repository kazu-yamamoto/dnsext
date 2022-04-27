module DNSC.Log (
  Level (..),
  new,
  none,
  ) where

import Control.Monad (when)
import System.IO (hSetBuffering, stdout, BufferMode (LineBuffering))

import DNSC.Concurrent (forkConsumeQueue)


data Level
  = DEBUG
  | INFO
  | NOTICE
  | WARN
  deriving (Eq, Ord, Show, Read)

new :: Level -> IO (Level -> [String] -> IO (), IO ())
new level = do
  hSetBuffering stdout LineBuffering

  (enqueue, quit) <- forkConsumeQueue $ putStr . unlines
  let logLines lv = when (level <= lv) . enqueue

  return (logLines, quit)

-- no logging
none :: Level -> [String] -> IO ()
none _ _ = return ()
