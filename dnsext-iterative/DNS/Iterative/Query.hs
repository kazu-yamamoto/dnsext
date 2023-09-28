module DNS.Iterative.Query (
    -- * Env
    Env,
    newEnv,

    -- * Iterative query
    resolveResponseIterative,
    getResponseIterative,

    -- * Cache
    getResponseCached,
    CacheResult (..),
) where

import DNS.Do53.Client
import DNS.Iterative.Query.API
import DNS.Iterative.Query.Env
import DNS.Iterative.Query.Types
import DNS.Types

resolveResponseIterative :: Env -> Domain -> TYPE -> QueryControls -> IO (Either String DNSMessage)
resolveResponseIterative env domain typ ictl = do
    ers <- runDNSQuery (getResultIterative domain typ) env ictl
    return $ replyMessage ers 0 {- dummy id -} [Question domain typ IN]
