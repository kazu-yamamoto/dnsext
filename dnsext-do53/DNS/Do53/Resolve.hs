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
resolve :: Seeds -> Domain -> TYPE -> QueryControls -> IO DNSMessage
resolve seeds@Seeds{..} dom typ qctl0
  | typ == AXFR   = E.throwIO InvalidAXFRLookup
  | concurrent    = resolveConcurrent dos
  | otherwise     = resolveSequential dos
  where
    concurrent = resolvConcurrent seedsResolvConf
    dos = makeInfo seeds dom typ qctl0

makeInfo :: Seeds -> Domain -> TYPE -> QueryControls -> [ResolvInfo]
makeInfo Seeds{..} dom typ qctl0 = go hps0 gens0
  where
    ResolvConf{..} = seedsResolvConf
    defaultResolvInfo = ResolvInfo {
        solvQuestion      = Question dom typ classIN
      , solvHostName      = "127.0.0.1" -- to be overwitten
      , solvPortNumber    = 53          -- to be overwitten
      , solvTimeout       = resolvTimeoutAction resolvTimeout
      , solvRetry         = resolvRetry
      , solvGenId         = return 0    -- to be overwitten
      , solvGetTime       = resolvGetTime
      , solvQueryControls = qctl0 <> resolvQueryControls
      , solvResolver      = resolvResolver
      }
    hps0 = seedsAddrPorts
    gens0 = seedsGenIds
    go ((h,p):hps) (gen:gens) = defaultResolvInfo { solvHostName = h, solvPortNumber = p, solvGenId = gen } : go hps gens
    go _ _ = []

resolveSequential :: [ResolvInfo] -> IO DNSMessage
resolveSequential sis0 = loop sis0
  where
    loop []       = error "resolveSequential:loop"
    loop [si]     = resolveOne si
    loop (si:sis) = do
        eres <- E.try $ resolveOne si
        case eres of
          Left (_ :: DNSError) -> loop sis
          Right res -> return res

resolveConcurrent :: [ResolvInfo] -> IO DNSMessage
resolveConcurrent sis =
    raceAny $ map resolveOne sis
  where
    raceAny ios = do
        asyncs <- mapM async ios
        snd <$> waitAnyCancel asyncs

resolveOne :: Resolver
resolveOne si = (solvResolver si) si
