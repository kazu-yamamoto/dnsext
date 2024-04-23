{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Env (
    Env (..),
    newEnv,
    newEmptyEnv,
    --
    getRootSep,
    getRootServers,
) where

-- GHC packages
import Data.IORef (newIORef)
import System.Timeout (timeout)

-- other packages

-- dnsext packages
import DNS.Do53.Internal (newConcurrentGenId)
import qualified DNS.RRCache as Cache
import DNS.TimeCache (TimeCache (..), noneTimeCache)
import DNS.Types (Domain, RCODE (..), ResourceRecord)

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Helpers (findDelegation, nsList)
import qualified DNS.Iterative.Query.LocalZone as Local
import DNS.Iterative.Query.Types
import DNS.Iterative.RootServers (rootServers, getRootServers)
import DNS.Iterative.RootTrustAnchors (getRootSep)
import DNS.Iterative.Stats

{- FOURMOLU_DISABLE -}
-- | Creating a new 'Env'.
newEnv
    :: Maybe ([ResourceRecord], [ResourceRecord])
    -> [(Domain, LocalZoneType, [ResourceRecord])]
    -> IO Env
newEnv root lzones = do
    let localName = Local.nameMap lzones
        localApex = Local.apexMap localName lzones
    rootHint <- getRootHint $ fromMaybe rootServers root
    newEmptyEnv <&> \env0 ->
        env0
            { rootHint_ = rootHint
            , lookupLocalApex_ = Local.lookupApex localApex
            , lookupLocalDomain_ = Local.lookupName localName
            }

newEmptyEnv :: IO Env
newEmptyEnv = do
    genId    <- newConcurrentGenId
    rootRef  <- newIORef Nothing
    stats <- newStats
    let TimeCache {..} = noneTimeCache
    rootHint <- getRootHint rootServers
    pure $
        Env
        { logLines_ = \_ _ ~_ -> pure ()
        , logDNSTAP_ = \_ -> pure ()
        , disableV6NS_ = False
        , rootAnchor_ = Nothing
        , rootHint_ = rootHint
        , lookupLocalApex_ = \_ -> Nothing
        , lookupLocalDomain_ = \_ _ -> Just (NoErr, [], [])
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

-- {-# ANN getRootHint ("HLint: ignore Use tuple-section") #-}
getRootHint :: ([ResourceRecord], [ResourceRecord]) -> IO Delegation
getRootHint (ns, as) = maybe (fail "getRootHint: bad configuration.") (pure . ($ [])) $ findDelegation (nsList (fromString ".") (,) ns) as
