{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Resolve (
    resolve
  ) where

import Control.Concurrent.Async (async, waitAnyCancel)
import Control.Exception as E
import DNS.Types

import DNS.Do53.Query
import DNS.Do53.Types

----------------------------------------------------------------

-- In lookup loop, we try UDP until we get a response.  If the response
-- is truncated, we try TCP once, with no further UDP retries.
--
-- For now, we optimize for low latency high-availability caches
-- (e.g.  running on a loopback interface), where TCP is cheap
-- enough.  We could attempt to complete the TCP lookup within the
-- original time budget of the truncated UDP query, by wrapping both
-- within a a single 'timeout' thereby staying within the original
-- time budget, but it seems saner to give TCP a full opportunity to
-- return results.  TCP latency after a truncated UDP reply will be
-- atypical.
--
-- Future improvements might also include support for TCP on the
-- initial query.
--
-- This function merges the query flag overrides from the resolver
-- configuration with any additional overrides from the caller.
--
resolve :: Resolver -> Domain -> TYPE -> QueryControls -> IO DNSMessage
resolve rlv dom typ qctl0
  | typ == AXFR   = E.throwIO InvalidAXFRLookup
  | concurrent    = resolveConcurrent dos
  | otherwise     = resolveSequential dos
  where
    concurrent = resolvConcurrent $ resolvConf rlv
    dos = makeDos rlv dom typ qctl0

makeDos :: Resolver -> Domain -> TYPE -> QueryControls -> [Do]
makeDos rlv dom typ qctl0 = go hps0 gens0
  where
    conf = resolvConf rlv
    defaultDo = Do {
        doQuestion      = Question dom typ classIN
      , doHostName      = "127.0.0.1" -- to be overwitten
      , doPortNumber    = 53          -- to be overwitten
      , doTimeout       = resolvTimeoutAction conf (resolvTimeout conf)
      , doRetry         = resolvRetry conf
      , doGenId         = return 0    -- to be overwitten
      , doGetTime       = resolvGetTime conf
      , doQueryControls = qctl0 <> resolvQueryControls conf
      , doX             = resolvDoX conf
      }
    hps0 = serverAddrs rlv
    gens0 = genIds rlv
    go ((h,p):hps) (gen:gens) = defaultDo { doHostName = h, doPortNumber = p, doGenId = gen } : go hps gens
    go _ _ = []

resolveSequential :: [Do] -> IO DNSMessage
resolveSequential dos0 = loop dos0
  where
    loop []       = error "resolveSequential:loop"
    loop [di]     = resolveOne di
    loop (di:dos) = do
        eres <- E.try $ resolveOne di
        case eres of
          Left (_ :: DNSError) -> loop dos
          Right res -> return res

resolveConcurrent :: [Do] -> IO DNSMessage
resolveConcurrent dos =
    raceAny $ map resolveOne dos
  where
    raceAny ios = do
        asyncs <- mapM async ios
        snd <$> waitAnyCancel asyncs

resolveOne :: DoX
resolveOne di = (doX di) di
