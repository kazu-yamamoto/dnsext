module DNSC.Concurrent (
  forkConsumeQueue,
  forkLoop,
  forksConsumeQueue,
  forksLoop,
  ) where

import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Monad (unless, replicateM_)
import Data.IORef (newIORef, readIORef, writeIORef)

import Control.Concurrent.Async (async, wait)


forkConsumeQueue :: (a -> IO ())
                 -> IO (a -> IO (), IO ())
forkConsumeQueue = forksConsumeQueue 1

forkLoop :: IO () -> IO (IO ())
forkLoop = forksLoop 1

forksConsumeQueue :: Int -> (a -> IO ())
                  -> IO (a -> IO (), IO ())
forksConsumeQueue n body = do
  inQ <- newChan
  let enqueue = writeChan inQ . Just
      issueQuit = replicateM_ n $ writeChan inQ Nothing
      loop = maybe (return ()) ((*> loop) . body) =<< readChan inQ

  waitQuit <- forksWithWait $ replicate n loop
  return (enqueue, issueQuit *> waitQuit)

forksLoop :: Int -> IO () -> IO (IO ())
forksLoop n body = do
  qref <- newIORef False
  let loop = do
        isQuit <- readIORef qref
        unless isQuit $ body *> loop
  waitQuit <- forksWithWait $ replicate n loop
  return $ writeIORef qref True *> waitQuit

forksWithWait :: [IO ()] -> IO (IO ())
forksWithWait bodies = do
  ts <- mapM async bodies
  let waitQuit = mapM_ wait ts
  return waitQuit
