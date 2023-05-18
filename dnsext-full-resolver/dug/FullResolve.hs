module FullResolve where

import Control.Concurrent (forkIO)
import Data.String (fromString)
import qualified DNS.Do53.Memo as Cache

import qualified DNS.Cache.Log as Log
import qualified DNS.Cache.TimeCache as TimeCache
import DNS.Cache.Iterative (Env (..), IterativeControls)
import qualified DNS.Cache.Iterative as Iterative

import DNS.Types

fullResolve :: Bool
            -> Log.Output
            -> Log.Level
            -> Log.DemoFlag
            -> IterativeControls
            -> String
            -> TYPE
            -> IO (Either String DNSMessage)
fullResolve disableV6NS logOutput logLevel logDemo ctl n ty = do
  (putLines, flushLog, loops, cxt) <- setup disableV6NS logOutput logLevel logDemo
  mapM_ forkIO $ loops
  out <- resolve cxt ctl n ty
  putLines Log.INFO Nothing ["--------------------"]
  flushLog
  return out

setup :: Bool -> Log.Output -> Log.Level -> Log.DemoFlag -> IO (Log.PutLines, IO (), [IO ()], Env)
setup disableV6NS logOutput logLevel logDemo = do
  (logLoop, putLines, _, flush) <- Log.new (Log.outputHandle logOutput) logLevel logDemo
  tcache@(getSec, _) <- TimeCache.new
  let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 getSec
  memo <- Cache.getMemo cacheConf
  let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
      ucache = (insert, Cache.readMemo memo)
  cxt <- Iterative.newEnv putLines disableV6NS ucache tcache
  return (putLines, flush, [logLoop], cxt)

resolve :: Env -> IterativeControls -> String -> TYPE -> IO (Either String DNSMessage)
resolve cxt ictl n ty =
  toMessage <$>
  Iterative.runDNSQuery (Iterative.replyResult domain ty) cxt ictl
  where
    domain = fromString n
    toMessage er = Iterative.replyMessage er 0 {- dummy id -} [Question domain ty classIN]
