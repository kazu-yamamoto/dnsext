{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Env (
    Env (..),
    newEnv,
) where

-- GHC packages
import Data.IORef (newIORef)

-- other packages

-- dnsext packages
import DNS.Do53.Client (Reply)
import DNS.Do53.Internal (newConcurrentGenId)
import qualified DNS.Log as Log
import DNS.RRCache (RRCacheOps (..))
import qualified DNS.TAP.Schema as DNSTAP
import DNS.TimeCache (TimeCache (..))

-- this package
import DNS.Iterative.Query.Types
import DNS.Iterative.Stats

-- | Creating a new 'Env'.
newEnv
    :: Log.PutLines
    -> (DNSTAP.Message -> IO ())
    -> Bool
    -- ^ disabling IPv6
    -> RRCacheOps
    -> TimeCache
    -> (IO Reply -> IO (Maybe Reply))
    -> IO Env
newEnv putLines putDNSTAP disableV6NS RRCacheOps{..} TimeCache{..} tmout = do
    genId <- newConcurrentGenId
    rootRef <- newIORef Nothing
    stats <- newStats
    let cxt =
            Env
                { logLines_ = putLines
                , logDNSTAP_ = putDNSTAP
                , disableV6NS_ = disableV6NS
                , insert_ = insertCache
                , getCache_ = readCache
                , expireCache_ = expireCache
                , currentRoot_ = rootRef
                , currentSeconds_ = getTime
                , timeString_ = getTimeStr
                , idGen_ = genId
                , stats_ = stats
                , timeout_ = tmout
                }
    return cxt
