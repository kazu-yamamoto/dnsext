{-# LANGUAGE FlexibleInstances #-}

module DNS.Iterative.Server.Queue (
    ReadQueue (..),
    WriteQueue (..),
    QueueSize (..),
    ReadQueueSTM (..),
    WriteQueueSTM (..),
    Queue,
    newQueue,
    newQueueChan,
    GetAny,
    makeGetAny,
    PutAny,
    makePutAny,
) where

import Control.Concurrent.Chan (Chan, newChan, readChan, writeChan)
import Control.Concurrent.STM (
    STM,
    TQueue,
    TVar,
    atomically,
    modifyTVar',
    newTQueue,
    newTVar,
    readTQueue,
    readTVar,
    writeTQueue,
    writeTVar,
 )
import Control.Monad

-- queue interface
data Queue m a = Queue
    { qReadQueue :: m a
    , qWriteQueue :: a -> m ()
    , qSizeMaxBound :: Int
    , qReadSize :: m Int
    , qReadLastMaxSize :: m Int
    }

class ReadQueue q where
    readQueue :: q a -> IO a

class WriteQueue q where
    writeQueue :: q a -> a -> IO ()

class QueueSize q where
    sizeMaxBound :: q a -> Int
    readSizes :: q a -> IO (Int, Int)

class ReadQueueSTM q where
    readQueueSTM :: q a -> STM a

class WriteQueueSTM q where
    writeQueueSTM :: q a -> a -> STM ()

instance ReadQueue (Queue IO) where
    readQueue = qReadQueue

instance WriteQueue (Queue IO) where
    writeQueue = qWriteQueue

instance QueueSize (Queue IO) where
    sizeMaxBound = qSizeMaxBound
    readSizes q = (,) <$> qReadSize q <*> qReadLastMaxSize q

instance ReadQueue (Queue STM) where
    readQueue = atomically . qReadQueue

instance WriteQueue (Queue STM) where
    writeQueue q = atomically . qWriteQueue q

instance QueueSize (Queue STM) where
    sizeMaxBound = qSizeMaxBound
    readSizes q = atomically $ (,) <$> qReadSize q <*> qReadLastMaxSize q

instance ReadQueueSTM (Queue STM) where
    readQueueSTM = qReadQueue

instance WriteQueueSTM (Queue STM) where
    writeQueueSTM = qWriteQueue

---

makeReadSizesAny :: QueueSize q => [q a] -> IO (Int, Int)
makeReadSizesAny qs = do
    (ss, xs) <- mapAndUnzipM readSizes qs
    return (sum ss, sum xs)

data GetAny a = GetAny
    { getAnyCycle :: TVar [STM a]
    , getAnyQueues :: Int
    , getAnyMaxBound :: Int
    , getAnyReadSizes :: IO (Int, Int)
    }

makeGetAny :: (ReadQueueSTM q, QueueSize q) => [q a] -> IO (GetAny a)
makeGetAny qs =
    atomically $
        do
            GetAny
            <$> newTVar c
            <*> pure (length qs)
            <*> pure (sum $ map sizeMaxBound qs)
            <*> pure (makeReadSizesAny qs)
  where
    c = cycle [readQueueSTM q | q <- qs]

getAnySTM :: GetAny a -> STM a
getAnySTM getA = do
    gs <- readTVar $ getAnyCycle getA
    a <- msum $ take (getAnyQueues getA) gs
    let z = tail gs
    z `seq` writeTVar (getAnyCycle getA) z
    return a

instance QueueSize GetAny where
    sizeMaxBound = getAnyMaxBound
    readSizes = getAnyReadSizes

instance ReadQueueSTM GetAny where
    readQueueSTM = getAnySTM

instance ReadQueue GetAny where
    readQueue = atomically . getAnySTM

data PutAny a = PutAny
    { putAnyCycle :: TVar [a -> STM ()]
    , putAnyQueues :: Int
    , putAnyMaxBound :: Int
    , putAnyReadSizes :: IO (Int, Int)
    }

makePutAny :: (WriteQueueSTM q, QueueSize q) => [q a] -> IO (PutAny a)
makePutAny qs =
    atomically $
        do
            PutAny
            <$> newTVar c
            <*> pure (length qs)
            <*> pure (sum $ map sizeMaxBound qs)
            <*> pure (makeReadSizesAny qs)
  where
    c = cycle [writeQueueSTM q | q <- qs]

putAnySTM :: PutAny a -> a -> STM ()
putAnySTM putA a = do
    ps <- readTVar $ putAnyCycle putA
    msum [put a | put <- take (putAnyQueues putA) ps]
    let z = tail ps
    z `seq` writeTVar (putAnyCycle putA) z

instance QueueSize PutAny where
    sizeMaxBound = putAnyMaxBound
    readSizes = putAnyReadSizes

instance WriteQueueSTM PutAny where
    writeQueueSTM = putAnySTM

instance WriteQueue PutAny where
    writeQueue putA = atomically . putAnySTM putA

---

data TQ a = TQ
    { tqContent :: TQueue a
    , tqSizeRef :: TVar Int
    , tqLastMaxSizeRef :: TVar Int
    , tqSizeMaxBound :: Int
    }

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

newQueue :: Int -> IO (Queue STM a)
newQueue xsz = do
    q <- atomically $ newTQ xsz
    let readSize = readTVar $ tqSizeRef q
    return $
        Queue
            (readTQ q)
            (writeTQ q)
            (tqSizeMaxBound q)
            readSize
            (max <$> readSize <*> readTVar (tqLastMaxSizeRef q))

instance ReadQueue TQ where
    readQueue = atomically . readTQ

instance WriteQueue TQ where
    writeQueue q = atomically . writeTQ q

instance QueueSize TQ where
    sizeMaxBound = tqSizeMaxBound
    readSizes = atomically . readSizesTQ

instance ReadQueueSTM TQ where
    readQueueSTM = readTQ

instance WriteQueueSTM TQ where
    writeQueueSTM = writeTQ

---

newQueueChan :: IO (Queue IO a)
newQueueChan = do
    q <- newChan
    return $ Queue (readChan q) (writeChan q) (-1) (return (-1)) (return (-1))

instance ReadQueue Chan where
    readQueue = readChan

instance WriteQueue Chan where
    writeQueue = writeChan

instance QueueSize Chan where
    sizeMaxBound _ = -1
    readSizes _ = return (-1, -1)
