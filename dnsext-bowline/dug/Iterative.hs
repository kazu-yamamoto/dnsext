{-# LANGUAGE RecordWildCards #-}

module Iterative (iterativeQuery) where

import DNS.Cache.Iterative (Env (..))
import qualified DNS.Cache.Iterative as Iterative
import DNS.Do53.Client (QueryControls)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import DNS.TimeCache (TimeCache(..), newTimeCache)
import Data.String (fromString)
import Network.Socket (HostName)

import DNS.Types

iterativeQuery
    :: Bool
    -> Log.PutLines
    -> QueryControls
    -> HostName
    -> TYPE
    -> IO (Either String DNSMessage)
iterativeQuery disableV6NS putLines ctl domain typ = do
    cxt <- setup disableV6NS putLines
    resolve cxt ctl domain typ

setup :: Bool -> Log.PutLines -> IO Env
setup disableV6NS putLines = do
    tcache@TimeCache{..} <- newTimeCache
    let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 getTime
    cacheOps <- Cache.newRRCacheOps cacheConf
    Iterative.newEnv putLines (\_ -> return ()) disableV6NS cacheOps tcache

resolve
    :: Env -> QueryControls -> String -> TYPE -> IO (Either String DNSMessage)
resolve cxt ictl n ty =
    toMessage
        <$> Iterative.runDNSQuery (Iterative.getResultIterative domain ty) cxt ictl
  where
    domain = fromString n
    toMessage er = Iterative.replyMessage er 0 {- dummy id -} [Question domain ty classIN]
