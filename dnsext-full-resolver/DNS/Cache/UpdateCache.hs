{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.UpdateCache (
  CacheConf (..),
  MemoActions (..),
  getDefaultStubConf,
  UpdateEvent,
  new,
  none,
  Insert,
  ) where

-- GHC packages
import Control.Monad (forever)
import Control.Concurrent (threadDelay)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Data.IORef (newIORef, readIORef, atomicWriteIORef)

-- dnsext-* packages
import DNS.Types (TTL)
import DNS.Types.Decode (EpochTime)

-- other packages
import UnliftIO (tryAny)

-- this package
import DNS.Cache.Cache (Cache, Key, CRSet, Ranking)
import qualified DNS.Cache.Cache as Cache

data CacheConf = CacheConf {
    maxCacheSize :: Int
  , memoActions :: MemoActions
  }

data MemoActions = MemoActions {
    memoLogLn :: String -> IO ()
  , memoErrorLn :: String -> IO ()
  , memoGetTime :: IO EpochTime
  , memoReadQueue :: IO UpdateEvent
  , memoWriteQueue :: UpdateEvent -> IO ()
  }

getDefaultStubConf :: Int -> IO EpochTime -> IO CacheConf
getDefaultStubConf size getSec = do
  let noLog _ = pure ()
  q <- newChan
  pure $ CacheConf size $ MemoActions noLog noLog getSec (readChan q) (writeChan q)


-- function update to update cache, and log action
type UpdateEvent = (Cache -> Maybe Cache, Cache -> IO ())

type Insert = Key -> TTL -> CRSet -> Ranking -> IO ()

new :: CacheConf
    -> IO ([IO ()], Insert, IO Cache, EpochTime -> IO ())
new CacheConf{..} = do
  let MemoActions{..} = memoActions
  cacheRef <- newIORef $ Cache.empty maxCacheSize

  let update1 :: UpdateEvent -> IO ()
      update1 (uevent, logAction) = do   -- step of single update theard
        cache <- readIORef cacheRef
        let updateRef c = do
              -- use atomicWrite to guard from out-of-order effect. to propagate updates to other CPU
              c `seq` atomicWriteIORef cacheRef c
              logAction c
        maybe (pure ()) updateRef $ uevent cache

  (updateLoop, enqueueU) <- do
    let errorLn = memoErrorLn . ("Memo.updateLoop: error: " ++) . show
        body = either errorLn return =<< tryAny (update1 =<< memoReadQueue)
    return (forever body, memoWriteQueue)

  let expires1 ts = enqueueU (Cache.expires ts, expiredLog)
        where
          expiredLog c = memoLogLn $ "some records expired: size = " ++ show (Cache.size c)

      expireEvsnts = forever body
        where
          errorLn = memoErrorLn . ("Memo.expireEvents: error: " ++) . show
          interval = threadDelay $ 1800 * 1000 * 1000  -- when there is no insert for a long time
          body = either errorLn return =<< tryAny (interval *> (expires1 =<< memoGetTime))

  let insert k ttl crs rank = do
        t <- memoGetTime
        let insert_ = Cache.insert t k ttl crs rank
            evInsert cache = maybe (insert_ cache) insert_ $ Cache.expires t cache {- expires before insert -}
        enqueueU (evInsert, const $ pure ())

  return ([updateLoop, expireEvsnts], insert, readIORef cacheRef, expires1)

-- no caching
none :: (Insert, IO Cache)
none =
  (\_ _ _ _ -> return (),
   return $ Cache.empty 0)
