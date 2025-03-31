{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module DNS.Iterative.Query.Types (
    VResult (..),
    queryParam,
    queryParamIN,
    queryControls',
    ContextT,
    chainedStateDS,
    QueryT,
    DNSQuery,
    runDNSQuery,
    handleResponseError,
) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (QueryControls)
import DNS.Do53.Internal (queryControls)
import DNS.Types
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Class

----------

queryParam :: Question -> QueryControls -> QueryParam
queryParam q = queryControls' $ queryParamH q

queryParamIN :: Domain -> TYPE -> QueryControls -> QueryParam
queryParamIN dom typ = queryParam (Question dom typ IN)

queryControls' :: (DNSFlags -> EDNSheader -> a) -> QueryControls -> a
queryControls' h = queryControls (\mf eh -> h (mf defaultQueryDNSFlags) eh)

----------

type ContextT m = ReaderT Env (ReaderT QueryParam (ReaderT QueryState m))
type QueryT m = ExceptT QueryError (ContextT m)
type DNSQuery = QueryT IO

instance MonadIO m => MonadEnv (QueryT m) where
    asksEnv = lift . asks
    {-# INLINEABLE asksEnv #-}

instance MonadIO m => MonadQP (QueryT m) where
    asksQP = lift . lift . asks
    {-# INLINEABLE asksQP #-}

instance MonadIO m => MonadQuery (QueryT m) where
    asksQS = lift . lift . lift . asks
    {-# INLINEABLE asksQS #-}
    throwQuery = throwE
    {-# INLINEABLE throwQuery #-}
    catchQuery = catchE
    {-# INLINEABLE catchQuery #-}

runDNSQuery' :: DNSQuery a -> Env -> QueryParam -> IO (Either QueryError a, QueryState)
runDNSQuery' q e p = do
    s <- newQueryState
    (,) <$> runReaderT (runReaderT (runReaderT (runExceptT q) e) p) s <*> pure s

runDNSQuery :: DNSQuery a -> Env -> QueryParam -> IO (Either QueryError a)
runDNSQuery q e p = fst <$> runDNSQuery' q e p

{- FOURMOLU_DISABLE -}
-- example instances
-- - responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- - responseErrDNSQuery = handleResponseError throwError pure  :: DNSMessage -> DNSQuery DNSMessage
handleResponseError :: [Address] -> (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError addrs e f msg = exerror $ \ee -> e $ ExtraError ee addrs $ Just msg
  where
    exerror eh
        | not (DNS.isResponse $ DNS.flags msg)              = eh   ErrorNotResp
        | InvalidEDNS <- DNS.ednsHeader msg                 = eh $ ErrorEDNS $ DNS.ednsHeader msg
        | DNS.rcode msg `notElem` [DNS.NoErr, DNS.NameErr]  = eh $ ErrorRCODE $ DNS.rcode msg
        | otherwise                                         = f msg
{- FOURMOLU_ENABLE -}

----------
-- Delegation

{- FOURMOLU_DISABLE -}
chainedStateDS :: Delegation -> Bool
chainedStateDS d = case delegationDS d of
    NotFilledDS _     -> False
    FilledDS []       -> False
    FilledDS (_ : _)  -> True
    AnchorSEP {}      -> True
{- FOURMOLU_ENABLE -}

----------
-- results

-- result tag from DNSSEC verification
data VResult
    = VR_Secure
    | VR_Insecure
    | VR_Bogus
    deriving (Show)
