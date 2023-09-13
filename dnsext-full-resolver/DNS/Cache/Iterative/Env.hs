{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Env (
    newEnv,
) where

-- GHC packages
import Data.IORef (newIORef)

-- other packages

-- dnsext packages
import DNS.Do53.Internal (newConcurrentGenId)
import DNS.Do53.RRCache (RRCacheOps(..))
import qualified DNS.Log as Log
import qualified DNS.TAP.Schema as DNSTAP

-- this package
import DNS.Cache.Iterative.Types
import DNS.Cache.TimeCache (TimeCache(..))

-- | Creating a new 'Env'.
newEnv
    :: Log.PutLines
    -> (DNSTAP.Message -> IO ())
    -> Bool
    -- ^ disabling IPv6
    -> RRCacheOps
    -> TimeCache
    -> IO Env
newEnv putLines putDNSTAP disableV6NS RRCacheOps{..} TimeCache{..} = do
    genId <- newConcurrentGenId
    rootRef <- newIORef Nothing
    let cxt =
            Env
                { logLines_ = putLines
                , logDNSTAP = putDNSTAP
                , disableV6NS_ = disableV6NS
                , insert_ = insertCache
                , getCache_ = readCache
                , expireCache = expireCache
                , currentRoot_ = rootRef
                , currentSeconds_ = getTime
                , timeString_ = getTimeStr
                , idGen_ = genId
                }
    return cxt
