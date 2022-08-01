module DNSC.Queue (
  ReadQueue (..),
  WriteQueue (..),
  QueueSize (..),
  TQ, newQueue,
  ChanQ, newQueueChan,
  Q1, newQueue1,
  ) where

import Control.Monad (guard, when)
import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.STM
  (TVar, newTVar, readTVar, modifyTVar', writeTVar,
   TMVar, newEmptyTMVar, takeTMVar, putTMVar, isEmptyTMVar,
   TQueue, newTQueue, readTQueue, writeTQueue,
   atomically, STM)


class ReadQueue q where
  readQueue :: q a -> IO a

class WriteQueue q where
  writeQueue :: q a -> a -> IO ()

class QueueSize q where
  sizeMaxBound :: q a -> Int
  readSizes :: q a -> IO (Int, Int)

---

data TQ a =
  TQ
  { tqContent :: TQueue a
  , tqSizeRef :: TVar Int
  , tqLastMaxSizeRef :: TVar Int
  , tqSizeMaxBound :: Int
  }

newQueue :: Int -> IO (TQ a)
newQueue = atomically . newTQ

newTQ :: Int -> STM (TQ a)
newTQ xsz = TQ <$> newTQueue <*> newTVar 0 <*> newTVar 0 <*> pure xsz

readTQ :: TQ a -> STM a
readTQ q = do
  x <- readTQueue $ tqContent q
  let szRef = tqSizeRef q
  sz <- readTVar szRef
  updateLastMax sz
  let nsz = pred sz
  nsz `seq` writeTVar szRef nsz
  return x
  where
    updateLastMax sz = do
      let lastMaxRef = tqLastMaxSizeRef q
      mx <- readTVar lastMaxRef
      when (sz > mx) $ writeTVar lastMaxRef sz

writeTQ :: TQ a -> a -> STM ()
writeTQ q x = do
  let szRef = tqSizeRef q
  sz <- readTVar szRef
  guard $ sz < tqSizeMaxBound q
  writeTQueue (tqContent q) x
  modifyTVar' szRef succ

readSizesTQ :: TQ a -> STM (Int, Int)
readSizesTQ q = do
  sz <- readTVar $ tqSizeRef q
  mx <- max sz <$> readTVar (tqLastMaxSizeRef q)
  return (sz, mx)

instance ReadQueue TQ where
  readQueue = atomically . readTQ

instance WriteQueue TQ where
  writeQueue q = atomically . writeTQ q

instance QueueSize TQ where
  sizeMaxBound = tqSizeMaxBound
  readSizes = atomically . readSizesTQ

---

type ChanQ = Chan

newQueueChan :: IO (ChanQ a)
newQueueChan = newChan

instance ReadQueue Chan where
  readQueue = readChan

instance WriteQueue Chan where
  writeQueue = writeChan

instance QueueSize Chan where
  sizeMaxBound _ = -1
  readSizes _ = return (-1, -1)

---

type Q1 = TMVar

newQueue1 :: IO (Q1 a)
newQueue1 = atomically newEmptyTMVar

instance ReadQueue TMVar where
  readQueue = atomically . takeTMVar

instance WriteQueue TMVar where
  writeQueue q = atomically . putTMVar q

instance QueueSize TMVar where
  sizeMaxBound _ = 1
  readSizes q = atomically $ (,) <$> (emptySize <$> isEmptyTMVar q) <*> pure (-1)
    where emptySize empty = if empty then 0 else 1
