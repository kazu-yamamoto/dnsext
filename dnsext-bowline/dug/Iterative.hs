{-# LANGUAGE RecordWildCards #-}

module Iterative (iterativeQuery, getRootV6) where

--
import Data.Functor
import Data.List.NonEmpty (NonEmpty (..))
import System.Timeout (timeout)

--
import Data.IP (IP (IPv6))
import DNS.Do53.Client (QueryControls)
import DNS.Iterative.Query (Env (..), newEmptyEnv, resolveResponseIterative, setRRCacheOps, setTimeCache)
import DNS.Iterative.Internal (Delegation (..), delegationEntry)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import DNS.TimeCache (getTime, newTimeCache)
import Network.Socket (PortNumber)

import DNS.Types

import Types (Options (..), shortLog)

{- FOURMOLU_DISABLE -}
getRootV6 :: IO [(IP, PortNumber)]
getRootV6 = do
    Env{rootHint_=Delegation{delegationNS=d:|ds}} <- newEmptyEnv
    pure $ foldr takeV6 [] $ d:ds
  where
    nlist (x:|xs) = x:xs
    ax _   _ n6 xs = [(IPv6 a, 53) | a      <- nlist n6]  ++ xs
    a6 _     n6 xs = [(IPv6 a, 53) | a      <- nlist n6]  ++ xs
    takeV6 = delegationEntry ax (\_ _ xs -> xs) a6 (\_ xs -> xs) (\_ xs -> xs) (\_ xs -> xs)
{- FOURMOLU_ENABLE -}

iterativeQuery
    :: (DNSMessage -> IO ())
    -> Log.PutLines IO
    -> (Question, QueryControls)
    -> Options
    -> IO ()
iterativeQuery putLn putLines qq opts = do
    env <- setup putLines opts
    er <- resolve env qq
    case er of
        Left e -> print e
        Right msg -> putLn msg

setup :: Log.PutLines IO -> Options -> IO Env
setup putLines opt@Options{..} = do
    tcache <- newTimeCache
    let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 $ getTime tcache
    cacheOps <- Cache.newRRCacheOps cacheConf
    let tmout = timeout 3000000
        setOps = setRRCacheOps cacheOps . setTimeCache tcache
    newEmptyEnv <&> \env0 ->
        (setOps env0)
            { shortLog_ = shortLog opt
            , logLines_ = putLines
            , disableV6NS_ = optDisableV6NS
            , timeout_ = tmout
            }

resolve
    :: Env -> (Question, QueryControls) -> IO (Either String DNSMessage)
resolve env (q, ctl) = resolveResponseIterative env q ctl
