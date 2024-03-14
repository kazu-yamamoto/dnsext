{-# LANGUAGE RecordWildCards #-}

module Iterative (iterativeQuery) where

import DNS.Do53.Client (QueryControls)
import DNS.Iterative.Query (Env, newEnv, resolveResponseIterative)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import DNS.TimeCache (TimeCache (..), newTimeCache)
import System.Timeout (timeout)

import DNS.Types

iterativeQuery
    :: Bool
    -> Log.PutLines
    -> (Domain, TYPE, QueryControls)
    -> IO (Either String DNSMessage)
iterativeQuery disableV6NS putLines q = do
    env <- setup disableV6NS putLines
    resolve env q

setup :: Bool -> Log.PutLines -> IO Env
setup disableV6NS putLines = do
    tcache@TimeCache{..} <- newTimeCache
    let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 getTime
    cacheOps <- Cache.newRRCacheOps cacheConf
    let tmout = timeout 3000000
    newEnv putLines (\_ -> return ()) disableV6NS Nothing Nothing [] cacheOps tcache tmout

resolve
    :: Env -> (Domain, TYPE, QueryControls) -> IO (Either String DNSMessage)
resolve env (d, t, ctl) = resolveResponseIterative env (Question d t IN) ctl
