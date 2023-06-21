module DNS.Cache.Iterative.Env (
    newEnv,
) where

-- GHC packages
import Data.IORef (newIORef)

-- other packages

-- dns packages

import DNS.Do53.Internal (
    newConcurrentGenId,
 )

-- this package
import DNS.Cache.Iterative.Types
import qualified DNS.Log as Log

newEnv
    :: Log.PutLines
    -> Bool
    -> UpdateCache
    -> TimeCache
    -> IO Env
newEnv putLines disableV6NS (ins, getCache) (curSec, timeStr) = do
    genId <- newConcurrentGenId
    rootRef <- newIORef Nothing
    let cxt =
            Env
                { logLines_ = putLines
                , disableV6NS_ = disableV6NS
                , insert_ = ins
                , getCache_ = getCache
                , currentRoot_ = rootRef
                , currentSeconds_ = curSec
                , timeString_ = timeStr
                , idGen_ = genId
                }
    return cxt
