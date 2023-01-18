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
resolve :: Seeds -> Question -> IO DNSMessage
resolve Seeds{..} q@Question{..}
  | qtype == AXFR = E.throwIO InvalidAXFRLookup
  | concurrent    = resolveConcurrent resolver q ris
  | otherwise     = resolveSequential resolver q ris
  where
    concurrent = seedsConcurrent
    resolver   = seedsResolver
    ris        = seedsResolvInfos

resolveSequential :: Resolver -> Question -> [ResolvInfo] -> IO DNSMessage
resolveSequential resolver q ris0 = loop ris0
  where
    loop []       = error "resolveSequential:loop"
    loop [ri]     = resolver q ri
    loop (ri:ris) = do
        eres <- E.try $ resolver q ri
        case eres of
          Left (_ :: DNSError) -> loop ris
          Right res -> return res

resolveConcurrent :: Resolver -> Question -> [ResolvInfo] -> IO DNSMessage
resolveConcurrent resolver q ris =
    raceAny $ map (resolver q) ris
  where
    raceAny ios = do
        asyncs <- mapM async ios
        snd <$> waitAnyCancel asyncs
