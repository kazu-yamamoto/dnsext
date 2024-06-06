module DNS.Iterative.Query (
    -- * Env
    module DNS.Iterative.Query.Env,

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
    ers <- runDNSQuery (getResultIterative q) env $ queryContext q ictl
    return $ replyMessage ers 0 {- dummy id -} [q]
