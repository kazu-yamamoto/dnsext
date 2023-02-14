module FullResolve where

import Control.Concurrent (forkIO)
import Data.String (fromString)
import qualified DNS.Types as DNS

import qualified DNS.Cache.Log as Log
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Cache.UpdateCache as UCache
import DNS.Cache.Iterative (Context (..), QueryError)
import qualified DNS.Cache.Iterative as Iterative

import DNS.Types

fullResolve :: Bool
            -> Log.Output
            -> Log.Level
            -> String
            -> TYPE
            -> IO (Either QueryError DNSMessage)
fullResolve disableV6NS logOutput logLevel n ty = do
  (putLines, flushLog, loops, cxt) <- setup disableV6NS logOutput logLevel
  mapM_ forkIO $ loops
  out <- resolve cxt n ty
  putLines Log.INFO ["--------------------"]
  flushLog
  return out

setup :: Bool -> Log.Output -> Log.Level -> IO (Log.Level -> [String] -> IO (), IO (), [IO ()], Context)
setup disableV6NS logOutput logLevel = do
  (logLoop, putLines, _, flush) <- Log.new (Log.outputHandle logOutput) logLevel
  tcache@(getSec, _) <- TimeCache.new
  cacheConf <- UCache.getDefaultStubConf (4 * 1024) 600 getSec
  (loops, insert, getCache, _) <- UCache.new cacheConf
  let ucache = (insert, getCache)
  cxt <- Iterative.newContext putLines disableV6NS ucache tcache
  return (putLines, flush, logLoop : loops, cxt)

resolve :: Context -> String -> TYPE -> IO (Either QueryError DNSMessage)
resolve cxt n ty = do
  fmap toMessage <$> Iterative.runResolve cxt (fromString n) ty
  where
    toMessage ((cnRRs, _), e) = either cached response e
      where
        cached (rc, ans, auth) = defaultResponse { DNS.header = h { DNS.flags = f }, DNS.answer = cnRRs ans, DNS.authority = auth }
          where
            h = DNS.header defaultResponse
            f = (DNS.flags h) { DNS.rcode = rc }
        response msg = msg { DNS.answer = cnRRs $ DNS.answer msg }
