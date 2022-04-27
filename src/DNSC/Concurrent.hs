module DNSC.Concurrent (
  forkConsumeQueue,
  forkLoop,
  forksConsumeQueue,
  forksLoop,
  forksConsumeQueueWith,
  forksLoopWith,
  ) where

-- GHC packages
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Monad (unless, replicateM_, (<=<))
import Data.IORef (newIORef, readIORef, writeIORef)
import System.IO.Error (tryIOError)

-- dns packages
import Control.Concurrent.Async (async, wait)


forkConsumeQueue :: (a -> IO ())
                 -> IO (a -> IO (), IO ())
forkConsumeQueue = forksConsumeQueue 1

forkLoop :: IO () -> IO (IO ())
forkLoop = forksLoop . (:[])

forksConsumeQueue :: Int -> (a -> IO ())
                  -> IO (a -> IO (), IO ())
forksConsumeQueue n = forksConsumeQueueWith n $ const $ return ()

forksLoop :: [IO ()] -> IO (IO ())
forksLoop = forksLoopWith $ const $ return ()

forksConsumeQueueWith :: Int -> (IOError -> IO ()) -> (a -> IO ())
                  -> IO (a -> IO (), IO ())
forksConsumeQueueWith n onError body = do
  inQ <- newChan
  let enqueue = writeChan inQ . Just
      issueQuit = replicateM_ n $ writeChan inQ Nothing
      hbody = either onError return <=< tryIOError . body
      loop = maybe (return ()) ((*> loop) . hbody) =<< readChan inQ

  waitQuit <- forksWithWait $ replicate n loop
  return (enqueue, issueQuit *> waitQuit)

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
