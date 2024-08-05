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
    --
    getLocalZones,
    --
    getStubZones,
) where

-- GHC packages
import Data.IORef (newIORef)
import qualified Data.List.NonEmpty as NE
import Data.Map (Map)
import qualified Data.Map as Map
import System.Timeout (timeout)

-- other packages

-- dnsext packages
import DNS.Do53.Internal (newConcurrentGenId)
import DNS.RRCache (RRCacheOps (..))
import qualified DNS.RRCache as Cache
import DNS.SEC
import DNS.TimeCache (TimeCache (..), noneTimeCache, getTime)
import DNS.Types
import DNS.ZoneFile (Record (R_RR))
import qualified DNS.ZoneFile as Zone

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Helpers
import qualified DNS.Iterative.Query.LocalZone as Local
import qualified DNS.Iterative.Query.StubZone as Stub
import DNS.Iterative.Query.Types
import qualified DNS.Iterative.Query.Verify as Verify
import DNS.Iterative.RootServers (getRootServers)
import DNS.Iterative.RootTrustAnchors (rootSepDS)
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
    let tc@TimeCache {..} = noneTimeCache
    pure $
        Env
        { shortLog_ = False
        , logLines_ = \_ _ ~_ -> pure ()
        , logDNSTAP_ = \_ -> pure ()
        , disableV6NS_ = False
        , rootAnchor_ = FilledDS [rootSepDS]
        , rootHint_ = rootHint
        , localZones_ = mempty
        , stubZones_ = mempty
        , maxNegativeTTL_ = 3600
        , insert_ = \_ _ _ _ -> pure ()
        , getCache_ = pure $ Cache.empty 0
        , expireCache_ = \_ -> pure ()
        , removeCache_ = \_ -> pure()
        , filterCache_ = \_ -> pure()
        , clearCache_ = pure ()
        , currentRoot_ = rootRef
        , currentSeconds_ = getTime tc
        , timeString_ = getTimeStr
        , idGen_ = genId
        , stats_ = stats
        , timeout_ = timeout 5000000
        }
{- FOURMOLU_ENABLE -}

---

setRRCacheOps :: RRCacheOps -> Env -> Env
setRRCacheOps RRCacheOps{..} env0 =
    env0
        { insert_ = insertCache
        , getCache_ = readCache
        , expireCache_ = expireCache
        , removeCache_ = removeCache
        , filterCache_ = filterCache
        , clearCache_ = clearCache
        }

setTimeCache :: TimeCache -> Env -> Env
setTimeCache tc@TimeCache{..} env0 =
    env0
        { currentSeconds_ = getTime tc
        , timeString_ = getTimeStr
        }

---

readRootHint :: FilePath -> IO Delegation
readRootHint = withRootDelegation fail pure <=< getRootServers

setRootHint :: Maybe Delegation -> Env -> Env
setRootHint md env0 = maybe env0 (\d -> env0 {rootHint_ = d}) md

---

type TrustAnchors = Map Domain MayFilledDS

{- FOURMOLU_DISABLE -}
readTrustAnchors :: [FilePath] -> IO TrustAnchors
readTrustAnchors ps = do
    pairs <- mapM readAnchor ps
    let (ds, ks) = unzip pairs
        dss  = ngroup $ concat ds
        keys = ngroup $ concat ks
        results = merge fst fst nullKEY nullDS cons dss keys
        lefts = ["  skipping, mismatch between DS and SEP, zone = " <> show n : map ("    " ++) e | (n, Left e) <- results]
    when (not $ null lefts) $ do
        putStrLn "trust-anchor: mismatch zone(s) are found"
        mapM_ (putStr . unlines) lefts
    pure $ Map.fromList [(n, r) | (n, Right r) <- results]
  where
    ngroup :: [(Domain, a)] -> [(Domain, [a])]
    ngroup = map repn . groupBy ((==) `on` fst) . sortOn fst
    repn xs = (fst $ head xs, map snd xs)
    --
    nullKEY (n,d) = ((n, pure $ FilledDS d) :)
    nullDS  (n,k) xs = list xs (\s ss -> (n, pure $ AnchorSEP [] $ s:|ss) : xs) k
    cons (n,d) (_,k) xs = either mismatch match $ Verify.sepDNSKEY d n k
      where
        mismatch e = (n, Left $ e : map show d ++ map show k) : xs
        match vs = case NE.unzip vs of (sep, ds:|dss) -> (n, pure $ AnchorSEP (ds:dss) sep) : xs
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
setRootAnchor as env0 = maybe env0 (\v -> env0 {rootAnchor_ = v }) $ Map.lookup (fromString ".") as

---

getLocalZones :: [(Domain, LocalZoneType, [ResourceRecord])] -> LocalZones
getLocalZones lzones = (Local.apexMap localName lzones, localName)
  where
    localName = Local.nameMap lzones

---

{- FOURMOLU_DISABLE -}
getStubZones :: [(Domain, [Domain], [Address])] -> TrustAnchors -> IO StubZones
getStubZones zones anchors = either fail pure $ Stub.getStubMap zones'
  where
    zones' = [ (apex, ns, as, dstate) | (apex, ns, as) <- zones, let dstate = fromMaybe (FilledDS []) $ Map.lookup apex anchors ]
{- FOURMOLU_ENABLE -}
