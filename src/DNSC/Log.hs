module DNSC.Log (
  Level (..),
  new,
  ) where

import Control.Concurrent (forkIO)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Monad (void, forever, when)
import System.IO (hSetBuffering, stdout, BufferMode (LineBuffering))

data Level
  = DEBUG
  | INFO
  | NOTICE
  | WARN
  deriving (Eq, Ord, Show, Read)

new :: Level -> IO (Level -> [String] -> IO ())
new level = do
  hSetBuffering stdout LineBuffering

  logQ <- newChan
  let flush1 = putStr . unlines =<< readChan logQ
  void $ forkIO $ forever flush1

  let logLines lv = when (level <= lv) . writeChan logQ

  return logLines
