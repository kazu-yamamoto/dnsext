{-# LANGUAGE FlexibleInstances #-}

module DNS.Iterative.Query.Types (
    RR,
    VResult (..),
    Result,
    ResultRRS',
    ResultRRS,
    queryParam,
    queryParamIN,
    queryControls',
    ContextT,
    chainedStateDS,
    ExtraError (..),
    extraError,
    QueryError (..),
    QueryT,
    DNSQuery,
    runDNSQuery,
    throwDnsError,
    handleQueryError,
    handleResponseError,

    -- re-exports
    MonadReaderQP (..),
    MonadReaderQS (..),
    setQS,
    getQS,
    --
    Env (..),
    LocalZoneType (..),
    LocalZones,
    StubZones,
    MayVerifiedRRS (..),
    mayVerifiedRRS,
    CasesNotValid (..),
    notValidNoSig,
    notValidCheckDisabled,
    notValidInvalid,
    RRset (..),
    CasesNotFilledDS (..),
    MayFilledDS (..),
    DFreshState (..),
    Address,
    Delegation (..),
    DEntry (..),
    --
    QueryParam (..),
    queryParamH,
    RequestDO (..),
    RequestCD (..),
    RequestAD (..),
    ednsHeaderCases,
    --
    QueryState (..),
    newQueryState,
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

data ExtraError
    = ErrorNotResp
    | ErrorEDNS DNS.EDNSheader
    | ErrorRCODE DNS.RCODE
    | ErrorBogus String
    deriving (Show)

{- FOURMOLU_DISABLE -}
extraError :: a -> (EDNSheader -> a) -> (RCODE -> a) -> (String -> a) -> ExtraError -> a
extraError notResp errEDNS errRCODE bogus fe = case fe of
    ErrorNotResp  -> notResp
    ErrorEDNS e   -> errEDNS e
    ErrorRCODE e  -> errRCODE e
    ErrorBogus s  -> bogus s
{- FOURMOLU_ENABLE -}

data QueryError
    = DnsError DNSError [String]
    | ExtraError ExtraError [Address] (Maybe DNSMessage)
    deriving (Show)

type ContextT m = ReaderT Env (ReaderT QueryParam (ReaderT QueryState m))
type QueryT m = ExceptT QueryError (ContextT m)
type DNSQuery = QueryT IO

instance Monad m => MonadReaderQP (QueryT m) where
    asksQP = lift . lift . asks
    {-# INLINEABLE asksQP #-}

instance Monad m => MonadReaderQS (QueryT m) where
    asksQS = lift . lift . lift . asks
    {-# INLINEABLE asksQS #-}

runDNSQuery' :: DNSQuery a -> Env -> QueryParam -> IO (Either QueryError a, QueryState)
runDNSQuery' q e p = do
    s <- newQueryState
    (,) <$> runReaderT (runReaderT (runReaderT (runExceptT q) e) p) s <*> pure s

runDNSQuery :: DNSQuery a -> Env -> QueryParam -> IO (Either QueryError a)
runDNSQuery q e p = fst <$> runDNSQuery' q e p

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwError . (`DnsError` [])

handleQueryError
    :: (QueryError -> DNSQuery a)
    -> (a -> DNSQuery a)
    -> DNSQuery a
    -> DNSQuery a
handleQueryError left right q = either left right =<< lift (runExceptT q)

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
-- alias

type RR = ResourceRecord

----------
-- results

-- result tag from DNSSEC verification
data VResult
    = VR_Secure
    | VR_Insecure
    | VR_Bogus
    deriving (Show)

---

{- response code, answer section, authority section -}
type Result = (RCODE, DNSFlags, [RR], [RR])
type ResultRRS' a = (a, [RRset], [RRset])
type ResultRRS = ResultRRS' RCODE
