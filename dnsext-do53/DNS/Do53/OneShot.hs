{-# LANGUAGE RecordWildCards    #-}

module DNS.Do53.OneShot (
      -- * Settings
      OneShotSettings
    , defaultOneShotSettings
      -- * Accessors
    , oneShotAction
    , oneShotDelay
      -- * Type
    , OneShot(..)
      -- * Creation
    , mkOneShot
    ) where

import Control.Concurrent (forkIO, threadDelay, killThread, ThreadId)
import Control.Exception (mask_)
import Data.IORef (IORef, newIORef, readIORef, writeIORef, atomicModifyIORef')

data OneShotSettings = OneShotSettings
    { oneShotAction :: IO () -> IO () -- ^ receive oneShotRegister, able to register again
    , oneShotDelay :: Int
    }

defaultOneShotSettings :: OneShotSettings
defaultOneShotSettings = OneShotSettings
    { oneShotAction = const $ putStrLn "one-shot action!"
    , oneShotDelay  = 30000000
    }

data OneShot = OneShot
    { oneShotRegister :: IO ()
    , oneShotKill :: IO ()
    }

-- | State of one-shot
data State = NoOneShot  -- ^ No one-shot thread
           | Workload   -- ^ one-shot job exists

mkOneShot :: OneShotSettings -> IO OneShot
mkOneShot settings = do
    stateRef <- newIORef NoOneShot
    tidRef   <- newIORef Nothing
    return OneShot {
        oneShotRegister = register settings stateRef tidRef
      , oneShotKill = kill tidRef
      }
  where
    kill tidRef = do
        mtid <- readIORef tidRef
        case mtid of
            Nothing  -> return ()
            Just tid -> killThread tid

register :: OneShotSettings
         -> IORef State -> IORef (Maybe ThreadId)
         -> IO ()
register settings stateRef tidRef =
    mask_ $ do
      next <- atomicModifyIORef' stateRef invoke
      next
  where
    invoke NoOneShot   = (Workload, spawn settings stateRef tidRef)
    invoke Workload    = (Workload, pure ())

spawn :: OneShotSettings
      -> IORef State -> IORef (Maybe ThreadId)
      -> IO ()
spawn settings stateRef tidRef = do
    tid <- forkIO $ oneShot settings stateRef tidRef
    writeIORef tidRef $ Just tid

oneShot :: OneShotSettings
      -> IORef State -> IORef (Maybe ThreadId)
        -> IO ()
oneShot settings@OneShotSettings{..} stateRef tidRef = do
    threadDelay oneShotDelay
    next <- atomicModifyIORef' stateRef close
    next
    {- do oneShotAction after close,
       to spawn new thread for register case -}
    oneShotAction $ register settings stateRef tidRef
  where
    close NoOneShot    = error "Control.OneShot.oneShot: unexpected NoOneShot"
    close Workload     = (NoOneShot, writeIORef tidRef Nothing)

{- $example1
Example of caching fibonacci numbers like Reaper

-- @

import Data.Time (UTCTime, getCurrentTime, diffUTCTime)
import Control.OneShot
import Control.Concurrent (threadDelay)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef')
import Control.Monad (forever, unless)
import System.Random (getStdRandom, randomR)

fib :: Int -> Int
fib 0 = 0
fib 1 = 1
fib n = fib (n-1) + fib (n-2)

type Cache = Map Int (Int, UTCTime)

main :: IO ()
main = do
  cacheRef <- newIORef Map.empty
  let again register = do
        nullP <- Map.null <$> readIORef cacheRef
        unless nullP register
  oneShot <- mkOneShot defaultOneShotSettings
    { oneShotAction = \registerAgain -> clean cacheRef *> registerAgain
    , oneShotDelay = 1000000 * 2 -- Clean 2 seconds after
    }
  forever $ do
    fibArg <- System.Random.getStdRandom (System.Random.randomR (30,34))
    cache <- readIORef cacheRef
    let cachedResult = Map.lookup fibArg cache
    case cachedResult of
      Just (fibResult, _createdAt) -> putStrLn $ "Found in cache: `fib " ++ show fibArg ++ "` " ++ show fibResult
      Nothing -> do
        let fibResult = fib fibArg
        putStrLn $ "Calculating `fib " ++ show fibArg ++ "` " ++ show fibResult
        time <- getCurrentTime
        atomicModifyIORef' cacheRef (\m -> (Map.insert fibArg (fibResult, time) m, ()))
        again $ oneShotRegister oneShot
    threadDelay 1000000 -- 1 second

-- Remove items > 10 seconds old
clean :: IORef Cache -> IO ()
clean cacheRef = do
  currentTime <- getCurrentTime
  let prune oldMap = (Map.filter (\ (_, createdAt) -> currentTime `diffUTCTime` createdAt < 10.0) oldMap, ())
  atomicModifyIORef' cacheRef prune

-- @

 -}
