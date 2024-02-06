{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.TestEnv where

-- GHC packages
import Data.IORef (newIORef, readIORef, writeIORef)

-- dnsext-* packages
import DNS.Types
import DNS.Types.Time
import qualified DNS.RRCache as Cache

-- this package
import DNS.Iterative.Query.Env (Env (..), newEmptyEnv)

newTestEnvNoCache :: ([String] -> IO ()) -> Bool -> IO Env
newTestEnvNoCache putLines disableV6NS = (\env -> env{logLines_ = \_ _ -> putLines, disableV6NS_ = disableV6NS}) <$> newEmptyEnv

newTestCache :: IO EpochTime -> Int -> IO (IO Cache.Cache, Question -> Seconds -> Cache.Hit -> Cache.Ranking -> IO ())
newTestCache getSec cacheSize = do
    cacheRef <- newIORef $ Cache.empty cacheSize
    let insert k ttl crs rank = do
            {- do not applying insertWithExpiresRRCache, because of the detached write thread in `Managed`.
               Want to check the result of writing immediately afterwards, so implement sequential logic. -}
            t <- getSec
            let withExpire = Cache.insertWithExpires t k ttl crs rank
            cache <- readIORef cacheRef
            maybe (pure ()) (writeIORef cacheRef) $ withExpire cache
    return (readIORef cacheRef, insert)

newTestEnv :: ([String] -> IO ()) -> Bool -> Int -> IO Env
newTestEnv putLines disableV6NS cacheSize = do
    env0@Env{..} <- newEmptyEnv
    (getCache, insert) <- newTestCache currentSeconds_ cacheSize
    pure $ env0{logLines_ = \_ _ -> putLines, disableV6NS_ = disableV6NS, insert_ = insert, getCache_ = getCache}
