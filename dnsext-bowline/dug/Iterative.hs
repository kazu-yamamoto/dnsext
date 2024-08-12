{-# LANGUAGE RecordWildCards #-}

module Iterative (iterativeQuery) where

import DNS.Do53.Client (QueryControls)
import DNS.Iterative.Query (Env (..), newEnv, resolveResponseIterative, setRRCacheOps, setTimeCache)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import DNS.TimeCache (newTimeCache, getTime)
import Data.Functor
import System.Timeout (timeout)

import DNS.Types

import Types (Options (..))

iterativeQuery
    :: (DNSMessage -> IO ())
    -> Log.PutLines
    -> (Question, QueryControls)
    -> Options
    -> IO ()
iterativeQuery putLn putLines qq opts = do
    env <- setup putLines opts
    er <- resolve env qq
    case er of
        Left e -> print e
        Right msg -> putLn msg

setup :: Log.PutLines -> Options -> IO Env
setup putLines Options{..} = do
    tcache <- newTimeCache
    let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 $ getTime tcache
    cacheOps <- Cache.newRRCacheOps cacheConf
    let tmout = timeout 3000000
        setOps = setRRCacheOps cacheOps . setTimeCache tcache
    newEnv <&> \env0 ->
        (setOps env0)
            { shortLog_ = optShortLog
            , logLines_ = putLines
            , disableV6NS_ = optDisableV6NS
            , timeout_ = tmout
            }

resolve
    :: Env -> (Question, QueryControls) -> IO (Either String DNSMessage)
resolve env (q, ctl) = resolveResponseIterative env q ctl
