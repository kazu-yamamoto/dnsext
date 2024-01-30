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

resolveResponseIterative :: Env -> Question -> QueryControls -> IO (Either String DNSMessage)
resolveResponseIterative env q ictl = do
    ers <- runDNSQuery (getResultIterative q) env $ QueryContext ictl q
    return $ replyMessage ers 0 {- dummy id -} [q]
