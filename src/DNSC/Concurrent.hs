module DNSC.Concurrent (
  forkConsumeQueue,
  forkLoop,
  forksConsumeQueue,
  forksLoop,
  forksConsumeQueueWith,
  forksLoopWith,
  ) where

-- GHC packages
import Control.Monad (unless, replicateM_, (<=<))
import Data.IORef (newIORef, readIORef, writeIORef)
import System.IO.Error (tryIOError)

-- dns packages
import Control.Concurrent.Async (async, wait)

-- this package hidden
import DNSC.Queue (newSizedQueue, readQueue, writeQueue)
import qualified DNSC.Queue as Queue


forkConsumeQueue :: (a -> IO ())
                 -> IO (a -> IO (), IO ())
forkConsumeQueue body = do
  (enqueue, _size, quit) <- forksConsumeQueue 1 body
  return (enqueue, quit)

forkLoop :: IO () -> IO (IO ())
forkLoop = forksLoop . (:[])

forksConsumeQueue :: Int -> (a -> IO ())
                  -> IO (a -> IO (), IO (Int, Int), IO ())
forksConsumeQueue n = forksConsumeQueueWith n $ const $ return ()

forksLoop :: [IO ()] -> IO (IO ())
forksLoop = forksLoopWith $ const $ return ()

forksConsumeQueueWith :: Int -> (IOError -> IO ()) -> (a -> IO ())
                  -> IO (a -> IO (), IO (Int, Int), IO ())
forksConsumeQueueWith n onError body = do
  inQ <- newSizedQueue $ 8 `max` n
  let enqueue = writeQueue inQ . Just
      issueQuit = replicateM_ n $ writeQueue inQ Nothing
      hbody = either onError return <=< tryIOError . body
      loop = maybe (return ()) ((*> loop) . hbody) =<< readQueue inQ

  waitQuit <- forksWithWait $ replicate n loop
  return (enqueue, (,) <$> Queue.readSize inQ <*> pure (Queue.maxSize inQ), issueQuit *> waitQuit)

forksLoopWith :: (IOError -> IO ()) -> [IO ()] -> IO (IO ())
forksLoopWith onError bodies = do
  qref <- newIORef False
  let handle = either onError return <=< tryIOError
      loop body = do
        isQuit <- readIORef qref
        unless isQuit $ handle body *> loop body
  waitQuit <- forksWithWait $ map loop bodies
  return $ writeIORef qref True *> waitQuit

forksWithWait :: [IO ()] -> IO (IO ())
forksWithWait bodies = do
  ts <- mapM async bodies
  let waitQuit = mapM_ wait ts
  return waitQuit
