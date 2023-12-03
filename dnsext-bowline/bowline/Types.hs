module Types where

import Control.Concurrent.STM
import Data.ByteString.Builder
import Data.IORef

data Command = Quit | Reload | KeepCache

data Control = Control
    { getStats :: IO Builder
    , getWStats :: IO Builder
    , quitServer :: IO ()
    , waitQuit :: STM ()
    , getCommandAndClear :: IO Command
    , setCommand :: Command -> IO ()
    }

newControl :: IO Control
newControl = do
    ref <- newIORef Quit
    return
        Control
            { getStats = return mempty
            , getWStats = return mempty
            , quitServer = return ()
            , waitQuit = return ()
            , getCommandAndClear = atomicModifyIORef' ref (\x -> (Quit, x))
            , setCommand = atomicWriteIORef ref
            }
