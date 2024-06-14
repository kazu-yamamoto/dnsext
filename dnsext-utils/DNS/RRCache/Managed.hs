{-# LANGUAGE RecordWildCards #-}

module DNS.RRCache.Managed (
    -- * Configuration
    RRCacheConf (..),
    getDefaultStubConf,
    noCacheConf,

    -- * High level operations
    RRCacheOps (..),
    noCacheOps,
    newRRCacheOps,

    -- * Resource record cache
    RRCache,
    newRRCache,

    -- * Operations
    insertWithExpiresRRCache,
    insertRRCache,
    lookupRRCache,
    expiresRRCache,
    keyForERR,
    keyForNX,
)
where

-- dnsext-* packages

-- this package
import DNS.RRCache.ReaperReduced
import DNS.RRCache.Types
import qualified DNS.RRCache.Types as Cache
import DNS.Types (TTL)
import DNS.Types.Time (EpochTime)

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
    let expiredLog c = rrCacheLogLn $ "some records expired: current size = " ++ show (Cache.size c)

    reaper <-
        mkReaper
            defaultReaperSettings
                { reaperAction = Cache.expires <$> rrCacheGetTime
                , reaperCallback = maybe (pure ()) expiredLog
                , reaperDelay = expiresDelay * 1000 * 1000
                , reaperNull = Cache.null
                , reaperEmpty = Cache.empty maxCacheSize
                }

    pure (RRCache conf reaper)

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
insertWithExpiresRRCache :: Question -> TTL -> Cache.Hit -> Ranking -> RRCache -> IO ()
insertWithExpiresRRCache k ttl crs rank (RRCache RRCacheConf{..} reaper) = do
    t <- rrCacheGetTime
    let withExpire = Cache.insertWithExpires t k ttl crs rank
    reaperUpdate reaper $ \cache -> maybe cache id $ withExpire cache

---
{- for stub. no alive check -}
lookupRRCache :: Question -> RRCache -> IO (Maybe (EpochTime, Cache.Hit))
lookupRRCache k rrCache = Cache.stubLookup k <$> readRRCache rrCache

{- for stub. not using current EpochTime -}
insertRRCache :: Question -> EpochTime -> Cache.Hit -> RRCache -> IO ()
insertRRCache k tim crs (RRCache _ reaper) = do
    let ins = Cache.stubInsert k tim crs
    reaperUpdate reaper $ \cache -> maybe cache id $ ins cache

{- NameError and other errors RCODE are cached using private ERR, instead of each type -}
keyForERR :: Question -> Question
keyForERR k = k{qtype = Cache.ERR}

{- Same as keyForERR, backword comapt -}
keyForNX :: Question -> Question
keyForNX = keyForERR

data RRCacheOps = RRCacheOps
    { insertCache :: Question -> TTL -> Cache.Hit -> Ranking -> IO ()
    , readCache :: IO Cache
    , expireCache :: EpochTime -> IO ()
    , stopCache :: IO ()
    }

noCacheOps :: RRCacheOps
noCacheOps = RRCacheOps (\_ _ _ _ -> pure ()) (pure $ Cache.empty 0) (\_ -> pure ()) (pure ())

newRRCacheOps :: RRCacheConf -> IO RRCacheOps
newRRCacheOps RRCacheConf{..} | maxCacheSize <= 0 = pure noCacheOps
newRRCacheOps cacheConf = do
    rrCache <- newRRCache cacheConf
    let insert_ k ttl crset rank = insertWithExpiresRRCache k ttl crset rank rrCache
        read_ = readRRCache rrCache
        expire_ now = expiresRRCache now rrCache
        stop_ = stopRRCache rrCache
    pure $ RRCacheOps insert_ read_ expire_ stop_

stopRRCache :: RRCache -> IO ()
stopRRCache (RRCache _ reaper) = reaperKill reaper
