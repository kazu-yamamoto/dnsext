module DNSC.Log (
  new,
  ) where

import Control.Concurrent (forkIO)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Monad (void, forever, when)
import System.IO (hSetBuffering, stdout, BufferMode (LineBuffering))

new :: Bool -> IO ([String] -> IO ())
new trace = do
  when trace $ hSetBuffering stdout LineBuffering

  logQ <- newChan
  let flush1 = putStr . unlines =<< readChan logQ
  void $ forkIO $ forever flush1

  let traceLines = when trace . writeChan logQ

  return traceLines
