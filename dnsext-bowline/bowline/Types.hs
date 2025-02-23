{-# LANGUAGE RecordWildCards #-}
module Types where

import Control.Concurrent.STM
import Data.ByteString.Builder
import Data.IORef

--
import DNS.Types
import DNS.Log (PutLines)
import DNS.RRCache (RRCacheOps)

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

data QuitCmd = Quit | Reload | KeepCache deriving Show

data Control = Control
    { getStats :: IO Builder
    , getWStats :: IO Builder
    , reopenLog :: IO ()
    , quitServer :: IO ()
    , waitQuit :: STM ()
    , getCommandAndClear :: IO QuitCmd
    , setCommand :: QuitCmd -> IO ()
    }

newControl :: IO Control
newControl = do
    ref <- newIORef Quit
    return
        Control
            { getStats = return mempty
            , getWStats = return mempty
            , reopenLog = return ()
            , quitServer = return ()
            , waitQuit = return ()
            , getCommandAndClear = atomicModifyIORef' ref (\x -> (Quit, x))
            , setCommand = atomicWriteIORef ref
            }

quitCmd :: Control -> QuitCmd -> IO ()
quitCmd Control{..} cmd = setCommand cmd >> quitServer
