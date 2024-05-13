{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Env (
    Env (..),
    newEnv,
    newEmptyEnv,
    --
    setRRCacheOps,
    setTimeCache,
    --
    readRootHint,
    setRootHint,
    --
    TrustAnchors,
    readTrustAnchors,
    setRootAnchor,
    getRootSep,
    getLocalZones,
) where

-- GHC packages
import Data.IORef (newIORef)
import Data.Map (Map)
import qualified Data.Map as Map
import System.Timeout (timeout)

-- other packages

-- dnsext packages
import DNS.Do53.Internal (newConcurrentGenId)
import DNS.RRCache (RRCacheOps (..))
import qualified DNS.RRCache as Cache
import DNS.SEC
import DNS.TimeCache (TimeCache (..), noneTimeCache)
import DNS.Types
import DNS.ZoneFile (Record (R_RR))
import qualified DNS.ZoneFile as Zone

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Helpers
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
        , rootHint_ = rootHint
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

readRootHint :: FilePath -> IO Delegation
readRootHint = withRootDelegation fail pure <=< getRootServers

setRootHint :: Maybe Delegation -> Env -> Env
setRootHint md env0 = maybe env0 (\d -> env0 {rootHint_ = d}) md

type TrustAnchors = Map Domain ([RD_DS], [RD_DNSKEY])

{- FOURMOLU_DISABLE -}
readTrustAnchors :: [FilePath] -> IO TrustAnchors
readTrustAnchors ps = do
    pairs <- mapM readAnchor ps
    let (ds, ks) = unzip pairs
        dss  = ngroup $ concat ds
        keys = ngroup $ concat ks
    pure $ Map.fromList $ merge' dss keys
  where
    ngroup :: [(Domain, a)] -> [(Domain, [a])]
    ngroup = map repn . groupBy ((==) `on` fst) . sortOn fst
    repn xs = (fst $ head xs, map snd xs)
    --
    nullKEY (n,d) = ((n, (d, [])) :)
    nullDS  (n,k) = ((n, ([], k)) :)
    cons (n,d) (_,k) = ((n, (d, k)) :)
    merge' = merge fst fst nullKEY nullDS cons
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
readAnchor :: FilePath -> IO ([(Domain, RD_DS)], [(Domain, RD_DNSKEY)])
readAnchor path = do
    rs <- Zone.parseFile path
    let rrs = [ rr | R_RR rr <- rs ]
        dss  = [ (rrname, ds) | ResourceRecord{ rrtype = DS    , .. } <- rrs, Just ds <- [fromRData rdata] ]
        keys = [ (rrname, ky) | ResourceRecord{ rrtype = DNSKEY, .. } <- rrs, Just ky <- [fromRData rdata] ]
    pure (dss, keys)
{- FOURMOLU_ENABLE -}

setRootAnchor :: TrustAnchors -> Env -> Env
setRootAnchor as env0 = maybe env0 (\(d,k) -> env0 {rootAnchor_ = Just (k,d) }) $ Map.lookup (fromString ".") as

getLocalZones :: [(Domain, LocalZoneType, [ResourceRecord])] -> LocalZones
getLocalZones lzones = (Local.apexMap localName lzones, localName)
  where
    localName = Local.nameMap lzones
