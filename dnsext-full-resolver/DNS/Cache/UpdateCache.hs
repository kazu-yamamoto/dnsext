{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.UpdateCache (
  new,
  none,
  Insert,
  ) where

-- GHC packages
import Control.Monad (forever)
import Control.Concurrent (threadDelay)
import Data.IORef (newIORef, readIORef, atomicWriteIORef)

-- dns packages
import DNS.Types (TTL)
import DNS.Types.Decode (EpochTime)

-- other packages
import UnliftIO (tryAny)

-- this package
import DNS.Cache.Queue (newQueue, readQueue, writeQueue)
import qualified DNS.Cache.Queue as Queue
import DNS.Cache.Cache (Cache, Key, CRSet, Ranking)
import qualified DNS.Cache.Cache as Cache

data CacheConf = CacheConf {
    memoActions :: MemoActions
  }

data MemoActions = MemoActions {
    memoLogLn :: String -> IO ()
  , memoErrorLn :: String -> IO ()
  }

data Update
  = I Key TTL CRSet Ranking
  | E
  deriving Show

runUpdate :: EpochTime -> Update -> Cache -> Maybe Cache
runUpdate t u cache = case u of
  I k ttl crs rank -> maybe (insert cache) insert $ Cache.expires t cache {- expires before insert -}
    where insert = Cache.insert t k ttl crs rank
  E                -> Cache.expires t cache

type Insert = Key -> TTL -> CRSet -> Ranking -> IO ()

new :: CacheConf
    -> IO EpochTime
    -> Int
    -> IO ([IO ()], Insert, IO Cache, EpochTime -> IO (), IO (Int, Int))
new CacheConf{..} getSec maxCacheSize = do
  let MemoActions{..} = memoActions
  cacheRef <- newIORef $ Cache.empty maxCacheSize

  let update1 (ts, u) = do   -- step of single update theard
        cache <- readIORef cacheRef
        let updateRef c = do
              -- use atomicWrite to guard from out-of-order effect. to propagate updates to other CPU
              c `seq` atomicWriteIORef cacheRef c
              case u of
                I {}  ->  return ()
                E     ->  memoLogLn $ "some records expired: size = " ++ show (Cache.size c)
        maybe (pure ()) updateRef $ runUpdate ts u cache

  (updateLoop, enqueueU, readUSize) <- do
    inQ <- newQueue 8
    let errorLn = memoErrorLn . ("Memo.updateLoop: error: " ++) . show
        body = either errorLn return =<< tryAny (update1 =<< readQueue inQ)
    return (forever body, writeQueue inQ, (,) <$> (fst <$> Queue.readSizes inQ) <*> pure (Queue.sizeMaxBound inQ))

  let expires1 ts = enqueueU =<< (,) ts <$> pure E

      expireEvsnts = forever body
        where
          errorLn = memoErrorLn . ("Memo.expireEvents: error: " ++) . show
          interval = threadDelay $ 1800 * 1000 * 1000  -- when there is no insert for a long time
          body = either errorLn return =<< tryAny (interval *> (expires1 =<< getSec))

  let insert k ttl crs rank =
        enqueueU =<< (,) <$> getSec <*> pure (I k ttl crs rank)

  return ([updateLoop, expireEvsnts], insert, readIORef cacheRef, expires1, readUSize)

-- no caching
none :: (Insert, IO Cache)
none =
  (\_ _ _ _ -> return (),
   return $ Cache.empty 0)
