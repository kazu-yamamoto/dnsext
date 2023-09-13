module Manage where

import Control.Concurrent.STM
import Data.IORef

data Control = Quit | Reload | KeepCache

data Manage = Manage
    { getStatus :: IO String
    , quitServer :: IO ()
    , waitQuit :: STM ()
    , getControlAndClear :: IO Control
    , setControl :: Control -> IO ()
    }

newManage :: IO Manage
newManage = do
    ref <- newIORef Quit
    return
        Manage
            { getStatus = return ""
            , quitServer = return ()
            , waitQuit = return ()
            , getControlAndClear = atomicModifyIORef' ref (\x -> (Quit, x))
            , setControl = atomicWriteIORef ref
            }
