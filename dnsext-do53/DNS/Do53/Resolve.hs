{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Resolve (
    resolve
  ) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (Async, async, cancel, waitCatchSTM)
import Control.Concurrent.STM
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
resolve :: ResolvEnv -> Question -> QueryControls -> IO Result
resolve _ Question{..} _
  | qtype == AXFR = E.throwIO InvalidAXFRLookup
resolve ResolvEnv{..} q qctl = case renvResolvInfos of
  []   -> error "resolve"
  [ri] -> resolver ri q qctl
  ris | concurrent -> resolveConcurrent ris resolver q qctl
      | otherwise  -> resolveSequential ris resolver q qctl
  where
    concurrent = renvConcurrent
    resolver   = renvResolver


resolveSequential :: [ResolvInfo] -> Resolver -> Question -> QueryControls -> IO Result
resolveSequential ris0 resolver q qctl = loop ris0
  where
    loop []       = error "resolveSequential:loop"
    loop [ri]     = resolver ri q qctl
    loop (ri:ris) = do
        eres <- E.try $ resolver ri q qctl
        case eres of
          Left (_ :: DNSError) -> loop ris
          Right res -> return res

resolveConcurrent :: [ResolvInfo] -> Resolver -> Question -> QueryControls -> IO Result
resolveConcurrent ris resolver q qctl = do
    r <- raceAny $ map (\ri -> resolver ri q qctl) ris
    if r == dummyResult then throwIO ServerFailure else return r
  where
    raceAny ios = do
        asyncs <- mapM async (sentinel:ios)
        snd <$> waitAnyRightCancel asyncs
    dummyResult = Result "" 0 "" (Reply defaultQuery 0 0)
    sentinel = do
        threadDelay 3000000 -- fixme
        return $ dummyResult

----------------------------------------------------------------

waitAnyRight :: [Async a] -> IO (Async a, a)
waitAnyRight = atomically . waitAnyRightSTM

waitAnyRightCancel :: [Async a] -> IO (Async a, a)
waitAnyRightCancel asyncs =
  waitAnyRight asyncs `finally` mapM_ cancel asyncs

waitAnyRightSTM :: [Async a] -> STM (Async a, a)
waitAnyRightSTM asyncs =
    foldr orElse retry $
      map (\a -> do r <- waitRightSTM a; return (a, r)) asyncs

waitRightSTM :: Async b -> STM b
waitRightSTM a = do
   r <- waitCatchSTM a
   either (const retry) return r -- this "retry" is the magic
