module DNS.Cache.Iterative.Env (
    newEnv,
    getUpdateCache,
) where

-- GHC packages
import Data.IORef (newIORef)

-- other packages

-- dnsext packages
import DNS.Do53.Internal (newConcurrentGenId)
import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.TAP.Schema as DNSTAP

-- this package
import DNS.Cache.Iterative.Types

getUpdateCache :: Cache.MemoConf -> IO UpdateCache
getUpdateCache cacheConf = do
    memo <- Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
        expire now = Cache.expiresMemo now memo
        read' = Cache.readMemo memo
    return (insert, read', expire)

-- | Creating a new 'Env'.
newEnv
    :: Log.PutLines
    -> (DNSTAP.Message -> IO ())
    -> Bool
    -- ^ disabling IPv6
    -> UpdateCache
    -> TimeCache
    -> IO Env
newEnv putLines putDNSTAP disableV6NS (ins, getCache, expire) (curSec, timeStr) = do
    genId <- newConcurrentGenId
    rootRef <- newIORef Nothing
    let cxt =
            Env
                { logLines_ = putLines
                , logDNSTAP = putDNSTAP
                , disableV6NS_ = disableV6NS
                , insert_ = ins
                , getCache_ = getCache
                , expireCache = expire
                , currentRoot_ = rootRef
                , currentSeconds_ = curSec
                , timeString_ = timeStr
                , idGen_ = genId
                }
    return cxt
