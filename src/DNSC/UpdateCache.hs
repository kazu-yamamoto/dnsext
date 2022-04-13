module DNSC.UpdateCache (
  newCache,
  ) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Monad (void, forever)
import Data.IORef (newIORef, readIORef, writeIORef)

import Network.DNS (TTL, Domain, TYPE, CLASS, ResourceRecord)

import qualified DNSC.Log as Log
import DNSC.Cache (Cache, Key, CRSet, Ranking, Timestamp, getTimestamp)
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

newCache :: (Log.Level -> [String] -> IO ()) -> IO (Lookup, Insert, IO Cache)
newCache putLines = do
  let putLn level = putLines level . (:[])
  cacheRef <- newIORef Cache.empty
  updateQ <- newChan

  let update1 = do   -- step of single update theard
        (ts, u) <- readChan updateQ
        cache <- readIORef cacheRef
        let updateRef c = do
              writeIORef cacheRef c
              case u of
                I {}  ->  return ()
                E     ->  putLn Log.NOTICE $ show ts ++ ": some records expired: size = " ++ show (Cache.size c)
        maybe (pure ()) updateRef $ runUpdate ts u cache
  void $ forkIO $ forever update1

  let expires1 = do
        threadDelay $ 1000 * 1000
        writeChan updateQ =<< (,) <$> getTimestamp <*> pure E
  void $ forkIO $ forever expires1

  let lookup_ dom typ cls = do
        cache <- readIORef cacheRef
        ts <- getTimestamp
        return $ Cache.lookup ts dom typ cls cache

      insert k ttl crs rank =
        writeChan updateQ =<< (,) <$> getTimestamp <*> pure (I k ttl crs rank)

  return (lookup_, insert, readIORef cacheRef)
