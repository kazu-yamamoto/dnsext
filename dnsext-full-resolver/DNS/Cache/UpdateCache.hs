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
import qualified DNS.Cache.Log as Log
import DNS.Cache.Cache (Cache, Key, CRSet, Ranking)
import qualified DNS.Cache.Cache as Cache

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

new :: (Log.Level -> [String] -> IO ()) -> (IO EpochTime, IO ShowS)
    -> Int
    -> IO ([IO ()], Insert, IO Cache, EpochTime -> IO (), IO (Int, Int))
new putLines (getSec, getTimeStr) maxCacheSize = do
  let putLn level = putLines level . (:[])
  cacheRef <- newIORef $ Cache.empty maxCacheSize

  let update1 (ts, tstr, u) = do   -- step of single update theard
        cache <- readIORef cacheRef
        let updateRef c = do
              -- use atomicWrite to guard from out-of-order effect. to propagate updates to other CPU
              c `seq` atomicWriteIORef cacheRef c
              case u of
                I {}  ->  return ()
                E     ->  putLn Log.NOTICE $ tstr $ ": some records expired: size = " ++ show (Cache.size c)
        maybe (pure ()) updateRef $ runUpdate ts u cache

  (updateLoop, enqueueU, readUSize) <- do
    inQ <- newQueue 8
    let errorLn = putLn Log.NOTICE . ("UpdateCache.updateLoop: error: " ++) . show
        body = either errorLn return =<< tryAny (update1 =<< readQueue inQ)
    return (forever body, writeQueue inQ, (,) <$> (fst <$> Queue.readSizes inQ) <*> pure (Queue.sizeMaxBound inQ))

  let expires1 ts = enqueueU =<< (,,) ts <$> getTimeStr <*> pure E

      expireEvsnts = forever body
        where
          errorLn = putLn Log.NOTICE . ("UpdateCache.expireEvents: error: " ++) . show
          interval = threadDelay $ 1800 * 1000 * 1000  -- when there is no insert for a long time
          body = either errorLn return =<< tryAny (interval *> (expires1 =<< getSec))

  let insert k ttl crs rank =
        enqueueU =<< (,,) <$> getSec <*> getTimeStr <*> pure (I k ttl crs rank)

  return ([updateLoop, expireEvsnts], insert, readIORef cacheRef, expires1, readUSize)

-- no caching
none :: (Insert, IO Cache)
none =
  (\_ _ _ _ -> return (),
   return $ Cache.empty 0)
