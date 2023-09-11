module Manage where

import Data.IORef
import Control.Concurrent.STM

data Manage = Manage {
    getStatus :: IO String
  , quitServer :: IO ()
  , waitQuit :: STM ()
  , getReloadAndClear :: IO Bool
  , setReload :: IO ()
  }

newManage :: IO Manage
newManage = do
    ref <- newIORef False
    return Manage {
        getStatus = return ""
      , quitServer = return ()
      , waitQuit = return ()
      , getReloadAndClear = atomicModifyIORef' ref (\x -> (False, x))
      , setReload = atomicWriteIORef ref True
      }
