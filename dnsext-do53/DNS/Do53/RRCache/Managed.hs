{-# LANGUAGE RecordWildCards #-}

module DNS.Do53.RRCache.Managed (
    RRCacheConf (..),
    RRCacheActions (..),
    getDefaultStubConf,
    noCacheConf,
    RRCache,
    readRRCache,
    expiresRRCache,
    insertWithExpiresRRCache,
    Prio,
    Entry,
    newRRCache,
    lookupCache,
    insertCache,
    keyForNX,
)
where

-- dnsext-* packages

-- this package
import DNS.Do53.RRCache.ReaperReduced
import DNS.Do53.RRCache.Types
import qualified DNS.Do53.RRCache.Types as Cache
import DNS.Types (TTL)
import DNS.Types.Decode (EpochTime)

data RRCacheConf = RRCacheConf
    { maxCacheSize :: Int
    , expiresDelay :: Int
    , memoActions :: RRCacheActions
    }

data RRCacheActions = RRCacheActions
    { memoLogLn :: String -> IO ()
    , memoGetTime :: IO EpochTime
    }

getDefaultStubConf :: Int -> Int -> IO EpochTime -> RRCacheConf
getDefaultStubConf sz delay getSec = RRCacheConf sz delay $ RRCacheActions noLog getSec
  where
    noLog ~_ = pure ()

noCacheConf :: RRCacheConf
noCacheConf = RRCacheConf 0 1800 $ RRCacheActions noLog (pure 0)
  where
    noLog ~_ = pure ()

data RRCache = RRCache RRCacheConf (Reaper Cache)

getRRCache :: RRCacheConf -> IO RRCache
getRRCache conf@RRCacheConf{..} = do
    let RRCacheActions{..} = memoActions
        expiredLog c = memoLogLn $ "some records expired: size = " ++ show (Cache.size c)

    reaper <-
        mkReaper
            defaultReaperSettings
                { reaperAction = Cache.expires <$> memoGetTime
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
insertWithExpiresRRCache :: Key -> TTL -> CRSet -> Ranking -> RRCache -> IO ()
insertWithExpiresRRCache k ttl crs rank (RRCache RRCacheConf{..} reaper) = do
    let RRCacheActions{..} = memoActions
    t <- memoGetTime
    let ins = Cache.insert t k ttl crs rank
        withExpire cache = maybe (ins cache) ins $ Cache.expires t cache {- expires before insert -}
    reaperUpdate reaper $ \cache -> maybe cache id $ withExpire cache

---
{- for stub -}

type Prio = EpochTime

type Entry = CRSet

newRRCache :: RRCacheConf -> IO RRCache
newRRCache = getRRCache

{- for stub. no alive check -}
lookupCache :: Key -> RRCache -> IO (Maybe (Prio, Entry))
lookupCache k memo = Cache.stubLookup k <$> readRRCache memo

{- for stub. not using current EpochTime -}
insertCache :: Key -> Prio -> Entry -> RRCache -> IO ()
insertCache k tim crs (RRCache _ reaper) = do
    let ins = Cache.stubInsert k tim crs
    reaperUpdate reaper $ \cache -> maybe cache id $ ins cache

{- NameError is cached using private NX, instead of each type -}
keyForNX :: Key -> Key
keyForNX k = k{qtype = Cache.NX}
