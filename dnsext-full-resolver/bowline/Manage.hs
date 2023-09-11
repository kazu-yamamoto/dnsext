module Manage where

import Control.Concurrent.STM
import Data.IORef

data Manage = Manage
    { getStatus :: IO String
    , quitServer :: IO ()
    , waitQuit :: STM ()
    , getReloadAndClear :: IO Bool
    , setReload :: IO ()
    }

newManage :: IO Manage
newManage = do
    ref <- newIORef False
    return
        Manage
            { getStatus = return ""
            , quitServer = return ()
            , waitQuit = return ()
            , getReloadAndClear = atomicModifyIORef' ref (\x -> (False, x))
            , setReload = atomicWriteIORef ref True
            }
