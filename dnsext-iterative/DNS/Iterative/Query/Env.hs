{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Env (
    Env (..),
    newEnv,
    newEmptyEnv,
    --
    setRRCacheOps,
    setTimeCache,
    --
    getRootSep,
    getRootHint,
    getLocalZones,
) where

-- GHC packages
import Data.IORef (newIORef)
import System.Timeout (timeout)

-- other packages

-- dnsext packages
import DNS.Do53.Internal (newConcurrentGenId)
import DNS.RRCache (RRCacheOps (..))
import qualified DNS.RRCache as Cache
import DNS.TimeCache (TimeCache (..), noneTimeCache)
import DNS.Types (Domain, ResourceRecord)

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Helpers (withRootDelegation)
import qualified DNS.Iterative.Query.LocalZone as Local
import DNS.Iterative.Query.Types
import DNS.Iterative.RootServers (getRootServers)
import DNS.Iterative.RootTrustAnchors (getRootSep)
import DNS.Iterative.Stats

{- FOURMOLU_DISABLE -}
-- | Creating a new 'Env'.
newEnv :: IO Env
newEnv = newEmptyEnv

newEmptyEnv :: IO Env
newEmptyEnv = do
    genId    <- newConcurrentGenId
    rootRef  <- newIORef Nothing
    stats <- newStats
    let TimeCache {..} = noneTimeCache
    pure $
        Env
        { logLines_ = \_ _ ~_ -> pure ()
        , logDNSTAP_ = \_ -> pure ()
        , disableV6NS_ = False
        , rootAnchor_ = Nothing
        , rootHint_ = Nothing
        , localZones_ = mempty
        , maxNegativeTTL_ = 3600
        , insert_ = \_ _ _ _ -> pure ()
        , getCache_ = pure $ Cache.empty 0
        , expireCache_ = \_ -> pure ()
        , currentRoot_ = rootRef
        , currentSeconds_ = getTime
        , timeString_ = getTimeStr
        , idGen_ = genId
        , stats_ = stats
        , timeout_ = timeout 5000000
        }
{- FOURMOLU_ENABLE -}

setRRCacheOps :: RRCacheOps -> Env -> Env
setRRCacheOps RRCacheOps{..} env0 =
    env0
        { insert_ = insertCache
        , getCache_ = readCache
        , expireCache_ = expireCache
        }

setTimeCache :: TimeCache -> Env -> Env
setTimeCache TimeCache{..} env0 =
    env0
        { currentSeconds_ = getTime
        , timeString_ = getTimeStr
        }

getRootHint :: FilePath -> IO Delegation
getRootHint = withRootDelegation fail pure <=< getRootServers

getLocalZones :: [(Domain, LocalZoneType, [ResourceRecord])] -> LocalZones
getLocalZones lzones = (Local.apexMap localName lzones, localName)
  where
    localName = Local.nameMap lzones
