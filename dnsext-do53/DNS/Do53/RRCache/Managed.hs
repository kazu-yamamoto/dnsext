{-# LANGUAGE RecordWildCards #-}

module DNS.Do53.RRCache.Managed (
    MemoConf (..),
    MemoActions (..),
    getDefaultStubConf,
    noCacheConf,
    Memo,
    getMemo,
    readMemo,
    expiresMemo,
    insertWithExpiresMemo,
    Prio,
    Entry,
    newCache,
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

data MemoConf = MemoConf
    { maxCacheSize :: Int
    , expiresDelay :: Int
    , memoActions :: MemoActions
    }

data MemoActions = MemoActions
    { memoLogLn :: String -> IO ()
    , memoGetTime :: IO EpochTime
    }

getDefaultStubConf :: Int -> Int -> IO EpochTime -> MemoConf
getDefaultStubConf sz delay getSec = MemoConf sz delay $ MemoActions noLog getSec
  where
    noLog ~_ = pure ()

noCacheConf :: MemoConf
noCacheConf = MemoConf 0 1800 $ MemoActions noLog (pure 0)
  where
    noLog ~_ = pure ()

data Memo = Memo MemoConf (Reaper Cache)

getMemo :: MemoConf -> IO Memo
getMemo conf@MemoConf{..} = do
    let MemoActions{..} = memoActions
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

    return (Memo conf reaper)

{- for full-resolver. lookup variants in Cache module
   - with alive checks which requires current EpochTime
   - with rank checks                                   -}
readMemo :: Memo -> IO Cache
readMemo (Memo _ reaper) = reaperRead reaper

expiresMemo :: EpochTime -> Memo -> IO ()
expiresMemo ts (Memo _ reaper) = reaperUpdate reaper expires_
  where
    expires_ c = maybe c id $ Cache.expires ts c

{- for full-resolver. using current EpochTime -}
insertWithExpiresMemo :: Key -> TTL -> CRSet -> Ranking -> Memo -> IO ()
insertWithExpiresMemo k ttl crs rank (Memo MemoConf{..} reaper) = do
    let MemoActions{..} = memoActions
    t <- memoGetTime
    let ins = Cache.insert t k ttl crs rank
        withExpire cache = maybe (ins cache) ins $ Cache.expires t cache {- expires before insert -}
    reaperUpdate reaper $ \cache -> maybe cache id $ withExpire cache

---
{- for stub -}

type Prio = EpochTime

type Entry = CRSet

newCache :: MemoConf -> IO Memo
newCache = getMemo

{- for stub. no alive check -}
lookupCache :: Key -> Memo -> IO (Maybe (Prio, Entry))
lookupCache k memo = Cache.stubLookup k <$> readMemo memo

{- for stub. not using current EpochTime -}
insertCache :: Key -> Prio -> Entry -> Memo -> IO ()
insertCache k tim crs (Memo _ reaper) = do
    let ins = Cache.stubInsert k tim crs
    reaperUpdate reaper $ \cache -> maybe cache id $ ins cache

{- NameError is cached using private NX, instead of each type -}
keyForNX :: Key -> Key
keyForNX k = k{qtype = Cache.NX}
