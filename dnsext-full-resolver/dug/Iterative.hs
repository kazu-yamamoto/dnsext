module Iterative (iterativeQuery) where

import qualified DNS.Do53.Memo as Cache
import Data.String (fromString)

import DNS.Cache.Iterative (Env (..), IterativeControls)
import qualified DNS.Cache.Iterative as Iterative
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Log as Log

import DNS.Types

iterativeQuery
    :: Bool
    -> Log.Output
    -> Log.Level
    -> IterativeControls
    -> String
    -> TYPE
    -> IO (Either String DNSMessage)
iterativeQuery disableV6NS logOutput logLevel ctl n ty = do
    (putLines, _, terminate) <- Log.new logOutput logLevel
    cxt <- setup disableV6NS putLines
    out <- resolve cxt ctl n ty
    terminate
    return out

setup :: Bool -> Log.PutLines -> IO Env
setup disableV6NS putLines = do
    tcache@(getSec, _) <- TimeCache.new
    let cacheConf = Cache.getDefaultStubConf (4 * 1024) 600 getSec
    memo <- Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
        ucache = (insert, Cache.readMemo memo)
    Iterative.newEnv putLines disableV6NS ucache tcache

resolve
    :: Env -> IterativeControls -> String -> TYPE -> IO (Either String DNSMessage)
resolve cxt ictl n ty =
    toMessage
        <$> Iterative.runDNSQuery (Iterative.replyResult domain ty) cxt ictl
  where
    domain = fromString n
    toMessage er = Iterative.replyMessage er 0 {- dummy id -} [Question domain ty classIN]
