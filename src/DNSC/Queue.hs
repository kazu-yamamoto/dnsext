module DNSC.Queue (
  Queue,
  newQueue,
  newSizedQueue,
  readQueue,
  writeQueue,
  ) where

import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)

type Queue a = Chan a

newQueue :: IO (Queue a)
newQueue = newChan

newSizedQueue :: Int -> IO (Queue a)
newSizedQueue = const newQueue

readQueue :: Queue a -> IO a
readQueue = readChan

writeQueue :: Queue a -> a -> IO ()
writeQueue = writeChan
