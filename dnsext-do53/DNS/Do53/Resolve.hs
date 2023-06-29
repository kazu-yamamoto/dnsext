{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Resolve (
    resolve,
)
where

import Control.Concurrent.Async (Async, async, cancel, waitCatchSTM, waitSTM)
import Control.Concurrent.STM
import Control.Exception as E
import DNS.Do53.Query
import DNS.Do53.Types
import qualified DNS.Log as Log
import DNS.Types

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
    [] -> error "resolve"
    [ri] -> resolver ri q qctl
    ris
        | concurrent -> resolveConcurrent ris resolver q qctl
        | otherwise -> resolveSequential ris resolver q qctl
  where
    concurrent = renvConcurrent
    resolver = renvResolver

resolveSequential
    :: [ResolvInfo] -> Resolver -> Question -> QueryControls -> IO Result
resolveSequential ris0 resolver q qctl = loop ris0
  where
    loop [] = error "resolveSequential:loop"
    loop [ri] = resolver ri q qctl
    loop (ri : ris) = do
        eres <- E.try $ resolver ri q qctl
        case eres of
            Left (_ :: DNSError) -> loop ris
            Right res -> return res

resolveConcurrent
    :: [ResolvInfo] -> Resolver -> Question -> QueryControls -> IO Result
resolveConcurrent [] _ _ _ = error "resolveConcurrent" -- never reach
resolveConcurrent ris@(ResolvInfo{..} : _) resolver q@Question{..} qctl = do
    r@Result{..} <- raceAny $ map (\ri -> resolver ri q qctl) ris
    let ~tag =
            "    query "
                ++ show qname
                ++ " "
                ++ show qtype
                ++ " to "
                ++ resultHostName
                ++ "#"
                ++ show resultPortNumber
                ++ "/"
                ++ resultTag
    ractionLog rinfoActions Log.DEMO Nothing [tag ++ ": win"]
    return r

----------------------------------------------------------------

raceAny :: [IO a] -> IO a
raceAny ios = mapM async ios >>= waitAnyRightCancel

waitAnyRightCancel :: [Async a] -> IO a
waitAnyRightCancel asyncs =
    atomically (waitAnyRightSTM asyncs) `finally` mapM_ cancel asyncs

-- The first value is returned and others are canceled at that time.
-- The last exception is returned when all throws an exception.
waitAnyRightSTM :: [Async a] -> STM a
waitAnyRightSTM [] = error "waitAnyRightSTM"
waitAnyRightSTM (a : as) = do
    let w = waitSTM a -- may throw an exception
        ws = map waitRightSTM as -- exeptions are ignored
        -- If "w" is reached, all of the others throw an exception.
    foldr orElse retry ws `orElse` w

waitRightSTM :: Async b -> STM b
waitRightSTM a = do
    r <- waitCatchSTM a
    -- Here this IO thread is dead.  A value of "Either SomeException
    -- a" is passed by "putTMVar".  After "retry", "waitCatchSTM" waits
    -- forever because "putTMVar" is never called again. Yes, the
    -- thread is dead already.  So, this transaction stays until
    -- canceled.
    either (const retry) return r
