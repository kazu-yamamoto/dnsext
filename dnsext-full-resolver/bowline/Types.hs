module Types where

import Control.Concurrent.STM
import Data.IORef

data Command = Quit | Reload | KeepCache

data Manage = Manage
    { getStatus :: IO String
    , quitServer :: IO ()
    , waitQuit :: STM ()
    , getCommandAndClear :: IO Command
    , setCommand :: Command -> IO ()
    }

newManage :: IO Manage
newManage = do
    ref <- newIORef Quit
    return
        Manage
            { getStatus = return ""
            , quitServer = return ()
            , waitQuit = return ()
            , getCommandAndClear = atomicModifyIORef' ref (\x -> (Quit, x))
            , setCommand = atomicWriteIORef ref
            }
