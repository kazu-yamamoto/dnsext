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
import Control.Monad (forever, unless, void)
import Control.Concurrent (forkIO, newChan, readChan, writeChan)
import Data.IORef (IORef, newIORef, readIORef, atomicWriteIORef)

-- dnsext-* packages
import DNS.Types (TTL)
import DNS.Types.Decode (EpochTime)
import DNS.Do53.OneShot (OneShot, defaultOneShotSettings, oneShotAction, oneShotDelay, mkOneShot, oneShotRegister)

-- other packages
import UnliftIO (tryAny)

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

data Memo = Memo MemoConf OneShot (IORef Cache)

expires_ :: MemoConf -> EpochTime -> IO ()
expires_ MemoConf{..} ts = memoWriteQueue (Cache.expires ts, expiredLog)
  where
    MemoActions{..} = memoActions
    expiredLog c = memoLogLn $ "some records expired: size = " ++ show (Cache.size c)

getMemo :: MemoConf -> IO (IO (), Memo)
getMemo conf@MemoConf{..} = do
  let MemoActions{..} = memoActions
  cacheRef <- newIORef $ Cache.empty maxCacheSize

  oneShotExpire <- mkOneShot defaultOneShotSettings
                   { oneShotAction = const (expires_ conf =<< memoGetTime)
                   , oneShotDelay = expiresDelay * 1000 * 1000
                   }

  let registerExpire c = unless (Cache.null c) $ oneShotRegister oneShotExpire
      update1 :: UpdateEvent -> IO ()
      update1 (uevent, logAction) = do   -- step of single update theard
        cache <- readIORef cacheRef
        let updateRef c = do
              -- use atomicWrite to guard from out-of-order effect. to propagate updates to other CPU
              c `seq` atomicWriteIORef cacheRef c
              logAction c
              registerExpire c
        maybe (registerExpire cache) updateRef $ uevent cache

  updateLoop <- do
    let errorLn = memoErrorLn . ("Memo.updateLoop: error: " ++) . show
        body = either errorLn return =<< tryAny (update1 =<< memoReadQueue)
    return $ forever body

  return (updateLoop, Memo conf oneShotExpire cacheRef)

{- for full-resolver. lookup variants in Cache module
   - with alive checks which requires current EpochTime
   - with rank checks                                   -}
readMemo :: Memo -> IO Cache
readMemo (Memo _ _ ref) = readIORef ref

expiresMemo :: EpochTime -> Memo -> IO ()
expiresMemo ts (Memo conf _ _) = expires_ conf ts

{- for full-resolver. using current EpochTime -}
insertWithExpiresMemo :: Key -> TTL -> CRSet -> Ranking -> Memo -> IO ()
insertWithExpiresMemo k ttl crs rank (Memo MemoConf{..} _ _) = do
  let MemoActions{..} = memoActions
  t <- memoGetTime
  let insert_ = Cache.insert t k ttl crs rank
      evInsert cache = maybe (insert_ cache) insert_ $ Cache.expires t cache {- expires before insert -}
  memoWriteQueue (evInsert, const $ pure ())

---
{- for stub -}

type Prio = EpochTime

type Entry = CRSet

newCache :: MemoConf -> IO Memo
newCache conf = do
  (updateLoop, memo) <- getMemo conf
  void $ forkIO updateLoop
  return memo

{- for stub. no alive check -}
lookupCache :: Key -> Memo -> IO (Maybe (Prio, Entry))
lookupCache k memo = Cache.stubLookup k <$> readMemo memo

{- for stub. not using current EpochTime -}
insertCache :: Key -> Prio -> Entry -> Memo -> IO ()
insertCache k tim crs (Memo MemoConf{..} _ _) = do
  let MemoActions{..} = memoActions
      evInsert = Cache.stubInsert k tim crs
  memoWriteQueue (evInsert, const $ pure ())

{- NameError is cached using private nxTYPE, instead of each type -}
keyForNX :: Key -> Key
keyForNX k = k { qtype = Cache.nxTYPE }
