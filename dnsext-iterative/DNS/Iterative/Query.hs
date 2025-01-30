module DNS.Iterative.Query (
    -- * Env
    module DNS.Iterative.Query.Env,

    -- * Iterative query
    resolveResponseIterative,
    foldResponseIterative,
    foldResponseIterative',

    -- * Cache
    foldResponseCached,
) where

import DNS.Do53.Client
import DNS.Iterative.Query.API
import DNS.Iterative.Query.Env
import DNS.Types

resolveResponseIterative :: Env -> Question -> QueryControls -> IO (Either String DNSMessage)
resolveResponseIterative env q ictl = foldResponseIterative' Left Right env 0 {- dummy id -} [q] q ictl
