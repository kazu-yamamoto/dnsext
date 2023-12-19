{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.TestEnv where

-- GHC packages
import Data.IORef (newIORef, readIORef, writeIORef)

-- dnsext-* packages
import qualified DNS.RRCache as Cache

-- this package
import DNS.Iterative.Query.Env (Env (..), newEmptyEnv)

newTestEnvNoCache :: ([String] -> IO ()) -> Bool -> IO Env
newTestEnvNoCache putLines disableV6NS = (\env -> env{logLines_ = \_ _ -> putLines, disableV6NS_ = disableV6NS}) <$> newEmptyEnv

newTestEnv :: ([String] -> IO ()) -> Bool -> Int -> IO Env
newTestEnv putLines disableV6NS cacheSize = do
    env0@Env{..} <- newEmptyEnv
    cacheRef <- newIORef $ Cache.empty cacheSize
    let insert k ttl crs rank = do
            {- do not applying insertWithExpiresRRCache, because of the detached write thread in `Managed`.
               Want to check the result of writing immediately afterwards, so implement sequential logic. -}
            t <- currentSeconds_
            let withExpire = Cache.insertWithExpires t k ttl crs rank
            cache <- readIORef cacheRef
            maybe (pure ()) (writeIORef cacheRef) $ withExpire cache
    pure $ env0{logLines_ = \_ _ -> putLines, disableV6NS_ = disableV6NS, insert_ = insert, getCache_ = readIORef cacheRef}
