{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.UpdateCache (
  MemoConf (..),
  MemoActions (..),
  getDefaultStubConf,
  UpdateEvent,
  new,
  none,
  Insert,
  ) where

-- GHC packages
import Control.Monad (forever, unless)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Data.IORef (newIORef, readIORef, atomicWriteIORef)

-- dnsext-* packages
import DNS.Types (TTL)
import DNS.Types.Decode (EpochTime)
import DNS.Do53.OneShot (defaultOneShotSettings, oneShotAction, oneShotDelay, mkOneShot, oneShotRegister)

-- other packages
import UnliftIO (tryAny)

-- this package
import DNS.Cache.Cache (Cache, Key, CRSet, Ranking)
import qualified DNS.Cache.Cache as Cache

data MemoConf = MemoConf {
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

getDefaultStubConf :: Int -> IO EpochTime -> IO MemoConf
getDefaultStubConf size getSec = do
  let noLog _ = pure ()
  q <- newChan
  pure $ MemoConf size $ MemoActions noLog noLog getSec (readChan q) (writeChan q)


-- function update to update cache, and log action
type UpdateEvent = (Cache -> Maybe Cache, Cache -> IO ())

type Insert = Key -> TTL -> CRSet -> Ranking -> IO ()

new :: MemoConf
    -> IO ([IO ()], Insert, IO Cache, EpochTime -> IO ())
new MemoConf{..} = do
  let MemoActions{..} = memoActions
  cacheRef <- newIORef $ Cache.empty maxCacheSize

  let expires1 ts = memoWriteQueue (Cache.expires ts, expiredLog)
        where
          expiredLog c = memoLogLn $ "some records expired: size = " ++ show (Cache.size c)

  oneShotExpire <- mkOneShot defaultOneShotSettings
                   { oneShotAction = const (expires1 =<< memoGetTime)
                   , oneShotDelay = 1800 * 1000 * 1000
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


  let insert k ttl crs rank = do
        t <- memoGetTime
        let insert_ = Cache.insert t k ttl crs rank
            evInsert cache = maybe (insert_ cache) insert_ $ Cache.expires t cache {- expires before insert -}
        memoWriteQueue (evInsert, const $ pure ())

  return ([updateLoop], insert, readIORef cacheRef, expires1)

-- no caching
none :: (Insert, IO Cache)
none =
  (\_ _ _ _ -> return (),
   return $ Cache.empty 0)
