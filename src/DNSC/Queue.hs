module DNSC.Queue (
  Queue,
  newQueue,
  newSizedQueue,
  readQueue,
  writeQueue,
  readSize, maxSize,
  ) where

import Control.Monad (guard)
import Control.Concurrent.STM
  (TVar, newTVar, readTVar, modifyTVar',
   TQueue, newTQueue, readTQueue, writeTQueue,
   atomically)

data Queue a =
  Queue
  { content :: TQueue a
  , sizeRef :: TVar Int
  , maxSize :: Int
  }


newQueue :: IO (Queue a)
newQueue = newSizedQueue 8

newSizedQueue :: Int -> IO (Queue a)
newSizedQueue xsz = atomically $ Queue <$> newTQueue <*> newTVar 0 <*> pure xsz

readQueue :: Queue a -> IO a
readQueue q = atomically $ do
  x <- readTQueue $ content q
  modifyTVar' (sizeRef q) pred
  return x

writeQueue :: Queue a -> a -> IO ()
writeQueue q x = atomically $ do
  let szRef = sizeRef q
  sz <- readTVar szRef
  guard $ sz < maxSize q
  writeTQueue (content q) x
  modifyTVar' szRef succ

readSize :: Queue a -> IO Int
readSize = atomically . readTVar . sizeRef

{-
type Queue a = Chan a

newQueue :: IO (Queue a)
newQueue = newChan

newSizedQueue :: Int -> IO (Queue a)
newSizedQueue = const newQueue

readQueue :: Queue a -> IO a
readQueue = readChan

writeQueue :: Queue a -> a -> IO ()
writeQueue = writeChan
 -}
