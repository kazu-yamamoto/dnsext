{-# LANGUAGE RecordWildCards #-}

module DNS.RRCache.Managed (
    -- * Configuration
    RRCacheConf (..),
    getDefaultStubConf,
    noCacheConf,

    -- * High level operations
    RRCacheOps (..),
    newRRCacheOps,

    -- * Resource record cache
    RRCache,
    newRRCache,

    -- * Operations
    insertWithExpiresRRCache,
    insertRRCache,
    lookupRRCache,
    expiresRRCache,
    keyForNX,
)
where

-- dnsext-* packages

-- this package
import DNS.RRCache.ReaperReduced
import DNS.RRCache.Types
import qualified DNS.RRCache.Types as Cache
import DNS.Types (TTL)
import DNS.Types.Decode (EpochTime)

data RRCacheConf = RRCacheConf
    { maxCacheSize :: Int
    , expiresDelay :: Int
    , rrCacheLogLn :: String -> IO ()
    , rrCacheGetTime :: IO EpochTime
    }

getDefaultStubConf :: Int -> Int -> IO EpochTime -> RRCacheConf
getDefaultStubConf sz delay getSec = RRCacheConf sz delay noLog getSec
  where
    noLog ~_ = pure ()

noCacheConf :: RRCacheConf
noCacheConf = RRCacheConf 0 1800 noLog (pure 0)
  where
    noLog ~_ = pure ()

data RRCache = RRCache RRCacheConf (Reaper Cache)

newRRCache :: RRCacheConf -> IO RRCache
newRRCache conf@RRCacheConf{..} = do
    let expiredLog c = rrCacheLogLn $ "some records expired: size = " ++ show (Cache.size c)

    reaper <-
        mkReaper
            defaultReaperSettings
                { reaperAction = Cache.expires <$> rrCacheGetTime
                , reaperCallback = maybe (return ()) expiredLog
                , reaperDelay = expiresDelay * 1000 * 1000
                , reaperNull = Cache.null
                , reaperEmpty = Cache.empty maxCacheSize
                }

    return (RRCache conf reaper)

{- for full-resolver. lookup variants in Cache module
   - with alive checks which requires current EpochTime
   - with rank checks                                   -}
readRRCache :: RRCache -> IO Cache
readRRCache (RRCache _ reaper) = reaperRead reaper

expiresRRCache :: EpochTime -> RRCache -> IO ()
expiresRRCache ts (RRCache _ reaper) = reaperUpdate reaper expires_
  where
    expires_ c = maybe c id $ Cache.expires ts c

{- for full-resolver. using current EpochTime -}
insertWithExpiresRRCache :: Question -> TTL -> CRSet -> Ranking -> RRCache -> IO ()
insertWithExpiresRRCache k ttl crs rank (RRCache RRCacheConf{..} reaper) = do
    t <- rrCacheGetTime
    let ins = Cache.insert t k ttl crs rank
        withExpire cache = maybe (ins cache) ins $ Cache.expires t cache {- expires before insert -}
    reaperUpdate reaper $ \cache -> maybe cache id $ withExpire cache

---
{- for stub. no alive check -}
lookupRRCache :: Question -> RRCache -> IO (Maybe (EpochTime, CRSet))
lookupRRCache k rrCache = Cache.stubLookup k <$> readRRCache rrCache

{- for stub. not using current EpochTime -}
insertRRCache :: Question -> EpochTime -> CRSet -> RRCache -> IO ()
insertRRCache k tim crs (RRCache _ reaper) = do
    let ins = Cache.stubInsert k tim crs
    reaperUpdate reaper $ \cache -> maybe cache id $ ins cache

{- NameError is cached using private NX, instead of each type -}
keyForNX :: Question -> Question
keyForNX k = k{qtype = Cache.NX}

data RRCacheOps = RRCacheOps
    { insertCache :: Question -> TTL -> CRSet -> Ranking -> IO ()
    , readCache :: IO Cache
    , expireCache :: EpochTime -> IO ()
    , stopCache :: IO ()
    }

newRRCacheOps :: RRCacheConf -> IO RRCacheOps
newRRCacheOps cacheConf = do
    rrCache <- newRRCache cacheConf
    let insert_ k ttl crset rank = insertWithExpiresRRCache k ttl crset rank rrCache
        read_ = readRRCache rrCache
        expire_ now = expiresRRCache now rrCache
        stop_ = stopRRCache rrCache
    return $ RRCacheOps insert_ read_ expire_ stop_

stopRRCache :: RRCache -> IO ()
stopRRCache (RRCache _ reaper) = reaperKill reaper
