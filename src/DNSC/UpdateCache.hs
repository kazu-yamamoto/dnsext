module DNSC.UpdateCache (
  new,
  none,
  Lookup,
  Insert,
  ) where

-- GHC packages
import Control.Concurrent (threadDelay)
import Data.IORef (newIORef, readIORef, atomicWriteIORef)

-- dns packages
import Network.DNS (TTL, Domain, TYPE, CLASS, ResourceRecord)

-- this package
import DNSC.Concurrent (forkLoop, forkConsumeQueue)
import DNSC.Types (Timestamp)
import qualified DNSC.Log as Log
import DNSC.Cache (Cache, Key, CRSet, Ranking)
import qualified DNSC.Cache as Cache

data Update
  = I Key TTL CRSet Ranking
  | E
  deriving Show

runUpdate :: Timestamp -> Update -> Cache -> Maybe Cache
runUpdate t u = case u of
  I k ttl crs rank -> Cache.insert t k ttl crs rank
  E                -> Cache.expires t

type Lookup = Domain -> TYPE -> CLASS -> IO (Maybe ([ResourceRecord], Ranking))
type Insert = Key -> TTL -> CRSet -> Ranking -> IO ()

new :: (Log.Level -> [String] -> IO ()) -> (IO Timestamp, IO ShowS)
    -> Int
    -> IO ((Lookup, Insert, IO Cache), IO ())
new putLines (getSec, getTimeStr) maxCacheSize = do
  let putLn level = putLines level . (:[])
  cacheRef <- newIORef $Cache.empty maxCacheSize

  let update1 (ts, tstr, u) = do   -- step of single update theard
        cache <- readIORef cacheRef
        let updateRef c = do
              -- use atomicWrite to guard from out-of-order effect. to propagate updates to other CPU
              atomicWriteIORef cacheRef c
              case u of
                I {}  ->  return ()
                E     ->  putLn Log.NOTICE $ tstr $ ": some records expired: size = " ++ show (Cache.size c)
        maybe (pure ()) updateRef $ runUpdate ts u cache
  (enqueueU, quitU) <- forkConsumeQueue update1

  let expires1 = do
        threadDelay $ 1000 * 1000
        enqueueU =<< (,,) <$> getSec <*> getTimeStr <*> pure E
  quitE <- forkLoop expires1

  let lookup_ dom typ cls = do
        cache <- readIORef cacheRef
        ts <- getSec
        return $ Cache.lookup ts dom typ cls cache

      insert k ttl crs rank =
        enqueueU =<< (,,) <$> getSec <*> getTimeStr <*> pure (I k ttl crs rank)

  return ((lookup_, insert, readIORef cacheRef), quitE *> quitU)

-- no caching
none :: (Lookup, Insert, IO Cache)
none =
  (\_ _ _ -> return Nothing,
   \_ _ _ _ -> return (),
   return $ Cache.empty 0)
