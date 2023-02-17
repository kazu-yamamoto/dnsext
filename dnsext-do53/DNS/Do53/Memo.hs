{-# LANGUAGE RecordWildCards #-}

module DNS.Do53.Memo (
  MemoConf (..),
  MemoActions (..),
  getDefaultStubConf,
  getNoCacheConf,
  UpdateEvent,
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

  module DNS.Do53.Cache,
  ) where

-- GHC packages
import Control.Concurrent (newChan, readChan, writeChan)

-- dnsext-* packages
import DNS.Types (TTL)
import DNS.Types.Decode (EpochTime)
import DNS.Do53.ReaperReduced

-- this package
import DNS.Do53.Cache
import qualified DNS.Do53.Cache as Cache

data MemoConf = MemoConf {
    maxCacheSize :: Int
  , expiresDelay :: Int
  , memoActions :: MemoActions
  }

data MemoActions = MemoActions {
    memoLogLn :: String -> IO ()
  , memoErrorLn :: String -> IO ()
  , memoGetTime :: IO EpochTime
  , memoReadQueue :: IO UpdateEvent
  , memoWriteQueue :: UpdateEvent -> IO ()
  }

getDefaultStubConf :: Int -> Int -> IO EpochTime -> IO MemoConf
getDefaultStubConf sz delay getSec = do
  let noLog _ = pure ()
  q <- newChan
  pure $ MemoConf sz delay $ MemoActions noLog noLog getSec (readChan q) (writeChan q)

getNoCacheConf :: IO MemoConf
getNoCacheConf = do
  let noLog _ = pure ()
  q <- newChan
  pure $ MemoConf 0 1800 $ MemoActions noLog noLog (pure 0) (readChan q) (\_ -> pure ())

-- function update to update cache, and log action
type UpdateEvent = (Cache -> Maybe Cache, Cache -> IO ())

data Memo = Memo MemoConf (Reaper Cache)

getMemo :: MemoConf -> IO (IO (), Memo)
getMemo conf@MemoConf{..} = do
  let MemoActions{..} = memoActions
      expiredLog c = memoLogLn $ "some records expired: size = " ++ show (Cache.size c)

  reaper <- mkReaper defaultReaperSettings
            { reaperAction = Cache.expires <$> memoGetTime
            , reaperCallback = maybe (return ()) expiredLog
            , reaperDelay = expiresDelay * 1000 * 1000
            , reaperNull = Cache.null
            , reaperEmpty = Cache.empty maxCacheSize
            }

  return (return (), Memo conf reaper)

{- for full-resolver. lookup variants in Cache module
   - with alive checks which requires current EpochTime
   - with rank checks                                   -}
readMemo :: Memo -> IO Cache
readMemo (Memo _ reaper) = reaperRead reaper

expiresMemo :: EpochTime -> Memo -> IO ()
expiresMemo ts (Memo _ reaper) = reaperUpdate reaper expires_
  where expires_ c = maybe c id $ Cache.expires ts c

{- for full-resolver. using current EpochTime -}
insertWithExpiresMemo :: Key -> TTL -> CRSet -> Ranking -> Memo -> IO ()
insertWithExpiresMemo k ttl crs rank (Memo MemoConf{..} reaper) = do
  let MemoActions{..} = memoActions
  t <- memoGetTime
  let ins = Cache.insert t k ttl crs rank
      withExpire cache = maybe (ins cache) ins $ Cache.expires t cache {- expires before insert -}
  reaperUpdate reaper $ \ cache -> maybe cache id $ withExpire cache

---
{- for stub -}

type Prio = EpochTime

type Entry = CRSet

newCache :: MemoConf -> IO Memo
newCache conf = snd <$> getMemo conf

{- for stub. no alive check -}
lookupCache :: Key -> Memo -> IO (Maybe (Prio, Entry))
lookupCache k memo = Cache.stubLookup k <$> readMemo memo

{- for stub. not using current EpochTime -}
insertCache :: Key -> Prio -> Entry -> Memo -> IO ()
insertCache k tim crs (Memo _ reaper) = do
  let ins = Cache.stubInsert k tim crs
  reaperUpdate reaper $ \ cache -> maybe cache id $ ins cache

{- NameError is cached using private nxTYPE, instead of each type -}
keyForNX :: Key -> Key
keyForNX k = k { qtype = Cache.nxTYPE }
