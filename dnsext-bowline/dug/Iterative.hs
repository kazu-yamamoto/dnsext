{-# LANGUAGE RecordWildCards #-}

module Iterative (iterativeQuery) where

import Data.Functor
import DNS.Do53.Client (QueryControls)
import DNS.Iterative.Query (Env (..), newEnv', resolveResponseIterative)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import DNS.TimeCache (TimeCache (..), newTimeCache)
import System.Timeout (timeout)

import DNS.Types

iterativeQuery
    :: Bool
    -> (DNSMessage -> IO ())
    -> Log.PutLines
    -> (Question, QueryControls)
    -> IO ()
iterativeQuery disableV6NS putLn putLines qq = do
    env <- setup disableV6NS putLines
    er <- resolve env qq
    case er of
        Left e -> print e
        Right msg -> putLn msg

setup :: Bool -> Log.PutLines -> IO Env
setup disableV6NS putLines = do
    TimeCache{..} <- newTimeCache
    let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 getTime
    Cache.RRCacheOps{..} <- Cache.newRRCacheOps cacheConf
    let tmout = timeout 3000000
    newEnv' Nothing [] <&> \env0 ->
        env0
            { logLines_ = putLines
            , disableV6NS_ = disableV6NS
            , insert_ = insertCache
            , getCache_ = readCache
            , expireCache_ = expireCache
            , currentSeconds_ = getTime
            , timeString_ = getTimeStr
            , timeout_ = tmout
            }

resolve
    :: Env -> (Question, QueryControls) -> IO (Either String DNSMessage)
resolve env (q, ctl) = resolveResponseIterative env q ctl
