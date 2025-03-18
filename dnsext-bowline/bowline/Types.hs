{-# LANGUAGE RecordWildCards #-}

module Types where

import Control.Concurrent.STM
import Control.Monad
import Data.ByteString.Builder
import Data.Functor
import Data.IORef
import System.IO.Error (tryIOError)

--

import DNS.Log (PutLines)
import DNS.RRCache (RRCacheOps)
import DNS.Types

import Config (Config)

{- FOURMOLU_DISABLE -}
data CacheControl = CacheControl
    { ccRemove          :: Domain -> IO ()
    , ccRemoveType      :: Domain -> TYPE -> IO ()
    , ccRemoveBogus     :: IO ()
    , ccRemoveNegative  :: IO ()
    , ccClear           :: IO ()
    }

data GlobalCache = GlobalCache
    { gcacheRRCacheOps  :: RRCacheOps
    , gcacheControl     :: CacheControl
    , gcacheSetLogLn    :: PutLines IO -> IO ()
    }
{- FOURMOLU_ENABLE -}

emptyCacheControl :: CacheControl
emptyCacheControl = CacheControl (\_ -> pure ()) (\_ _ -> pure ()) (pure ()) (pure ()) (pure ())

data QuitCmd = Quit | Reload Config | KeepCache Config deriving (Show)

data Control = Control
    { getStats :: IO Builder
    , getWStats :: IO Builder
    , reopenLog :: IO ()
    , getConfig :: IO (Either IOError Config)
    , quitServer :: IO ()
    , waitQuit :: STM ()
    , getCommandAndClear :: IO QuitCmd
    , setCommand :: QuitCmd -> IO ()
    }

newControl :: IO Config -> IO Control
newControl readConfig = do
    qRef <- newTVarIO False
    ref <- newIORef Quit
    return
        Control
            { getStats = return mempty
            , getWStats = return mempty
            , reopenLog = return ()
            , getConfig = tryIOError readConfig
            , quitServer = atomically $ writeTVar qRef True
            , waitQuit = readTVar qRef >>= guard
            , getCommandAndClear = atomicModifyIORef' ref (\x -> (Quit, x))
            , setCommand = atomicWriteIORef ref
            }

quitCmd :: Control -> QuitCmd -> IO ()
quitCmd Control{..} cmd = setCommand cmd >> quitServer

reloadCmd :: Control -> (Config -> QuitCmd) -> a -> a -> IO a
reloadCmd ctl@Control{..} rcmd lv rv = do
    either left right =<< getConfig
  where
    left e = putStrLn ("reload failed: " ++ show e) $> lv
    right conf = quitCmd ctl (rcmd conf) $> rv
