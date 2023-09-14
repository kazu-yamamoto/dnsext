module DNS.Iterative.Query (
    -- * resolve interfaces
    newEnv,
    getResponseIterative,
    CacheResult (..),
    getResponseCached,
    getResultIterative,
    getResultCached,
    replyMessage,

    -- * types
    module DNS.Iterative.Query.Types,

    -- * testing
    runResolve,
    runResolveExact,
    runResolveJust,
    rootHint,
    runIterative,
    printResult,
    refreshRoot,
    rootPriming,
    rrsetValid,
) where

import DNS.Iterative.Query.API
import DNS.Iterative.Query.Env
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Resolve
import DNS.Iterative.Query.ResolveJust
import DNS.Iterative.Query.Root
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
