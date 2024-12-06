{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Types (
    RR,
    Result,
    ResultRRS',
    ResultRRS,
    LocalZoneType (..),
    LocalZones,
    StubZones,
    Env (..),
    QueryParam (..),
    queryParam,
    queryParamIN,
    RequestDO (..),
    RequestCD (..),
    RequestAD (..),
    QueryState (..),
    RRset (..),
    Address,
    DEntry (..),
    ContextT,
    CasesNotFilledDS (..),
    MayFilledDS (..),
    Delegation (..),
    chainedStateDS,
    ExtraError (..),
    extraError,
    QueryError (..),
    DNSQuery,
    MonadReaderQP (..),
    MonadReaderQS (..),
    CasesNotValid (..),
    notValidNoSig,
    notValidCheckDisabled,
    notValidInvalid,
    MayVerifiedRRS (..),
    mayVerifiedRRS,
    DFreshState (..),
    runDNSQuery,
    throwDnsError,
    handleQueryError,
    handleResponseError,
) where

-- GHC packages
import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef')
import Data.Map.Strict (Map)

-- other packages

-- dnsext packages
import DNS.Do53.Client (EdnsControls (..), FlagOp (..), HeaderControls (..), QueryControls (..), Reply)
import qualified DNS.Log as Log
import DNS.RRCache (Cache, Ranking)
import qualified DNS.RRCache as Cache
import DNS.SEC
import qualified DNS.TAP.Schema as DNSTAP
import DNS.Types hiding (InvalidEDNS)
import qualified DNS.Types as DNS
import Data.IP (IP, IPv4, IPv6)
import Network.Socket (PortNumber)

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Stats

----------
-- Local Zone

{- FOURMOLU_DISABLE -}
data LocalZoneType
    = LZ_Deny
    | LZ_Refuse
    | LZ_Static
    {- LZ_Transparent -}
    {- LZ_TypeTransparent -}
    | LZ_Redirect
    deriving Show
{- FOURMOLU_ENABLE -}

type LocalZones = (Map Domain [(Domain, LocalZoneType, [RRset])], Map Domain [RRset])
type StubZones = Map Domain [Delegation]

----------
-- Monad and context

data Env = Env
    { shortLog_ :: Bool
    , logLines_ :: Log.PutLines IO
    , logDNSTAP_ :: DNSTAP.Message -> IO ()
    , disableV6NS_ :: Bool
    , rootAnchor_ :: MayFilledDS
    , rootHint_ :: Delegation
    , localZones_ :: LocalZones
    , stubZones_ :: StubZones
    , maxNegativeTTL_ :: TTL
    , failureRcodeTTL_ :: TTL
    , insert_ :: Question -> TTL -> Cache.Hit -> Ranking -> IO ()
    , getCache_ :: IO Cache
    , expireCache_ :: EpochTime -> IO ()
    , removeCache_ :: Question -> IO ()
    , filterCache_ :: (Question -> EpochTime -> Cache.Hit -> Ranking -> Bool) -> IO ()
    , clearCache_ :: IO ()
    , currentRoot_ :: IORef (Maybe Delegation)
    , currentSeconds_ :: IO EpochTime
    , currentTimeUsec_ :: IO EpochTimeUsec
    , timeString_ :: IO ShowS
    , idGen_ :: IO DNS.Identifier
    , stats_ :: Stats
    , updateHistogram_ :: Integer -> Stats -> IO ()
    , timeout_ :: IO Reply -> IO (Maybe Reply)
    }

data QueryParam = QueryParam
    { origQuestion_ :: Question
    , requestDO_ :: RequestDO
    , requestCD_ :: RequestCD
    , requestAD_ :: RequestAD
    }

queryParam :: Question -> QueryControls -> QueryParam
queryParam q qctl = QueryParam q (toRequestDO qctl) (toRequestCD qctl) (toRequestAD qctl)

queryParamIN :: Domain -> TYPE -> QueryControls -> QueryParam
queryParamIN dom typ qctl = queryParam (Question dom typ IN) qctl

{- Datatypes for request flags to pass iterative query.
  * DO (DNSSEC OK) must be 1 for DNSSEC available resolver
    * https://datatracker.ietf.org/doc/html/rfc4035#section-3.2.1 The DO Bit
  * CD (Checking Disabled)
  * AD (Authenticated Data)
    * https://datatracker.ietf.org/doc/html/rfc6840#section-5.7 Setting the AD Bit on Queries
      "setting the AD bit in a query as a signal indicating that the requester understands
       and is interested in the value of the AD bit in the response" -}
data RequestDO
    = DnssecOK
    | NoDnssecOK
    deriving (Eq, Show)

data RequestCD
    = CheckDisabled
    | NoCheckDisabled
    deriving (Eq, Show)

data RequestAD
    = AuthenticatedData
    | NoAuthenticatedData
    deriving (Eq, Show)

toRequestDO :: QueryControls -> RequestDO
toRequestDO qctl = case extDO $ qctlEdns qctl of
    FlagSet -> DnssecOK
    _ -> NoDnssecOK

toRequestCD :: QueryControls -> RequestCD
toRequestCD qctl = case cdBit $ qctlHeader qctl of
    FlagSet -> CheckDisabled
    _ -> NoCheckDisabled

toRequestAD :: QueryControls -> RequestAD
toRequestAD qctl = case adBit $ qctlHeader qctl of
    FlagSet -> AuthenticatedData
    _ -> NoAuthenticatedData

data QueryState = QueryState
    { setQueryCount_ :: Int -> IO ()
    , getQueryCount_ :: IO Int
    }

newQueryState :: IO QueryState
newQueryState = do
    cref <- newIORef 0
    let set x = atomicModifyIORef' cref (\_ -> (x, ()))
    pure $ QueryState set $ readIORef cref

data ExtraError
    = ErrorNotResp
    | ErrorEDNS DNS.EDNSheader
    | ErrorRCODE DNS.RCODE
    deriving (Show)

{- FOURMOLU_DISABLE -}
extraError :: a -> (EDNSheader -> a) -> (RCODE -> a) -> ExtraError -> a
extraError notResp errEDNS errRCODE fe = case fe of
    ErrorNotResp  -> notResp
    ErrorEDNS e   -> errEDNS e
    ErrorRCODE e  -> errRCODE e
{- FOURMOLU_ENABLE -}

data QueryError
    = DnsError DNSError [String]
    | ExtraError ExtraError [Address] DNSMessage
    deriving (Show)

type ContextT m = ReaderT Env (ReaderT QueryParam (ReaderT QueryState m))
type DNSQuery = ExceptT QueryError (ContextT IO)

class Monad m => MonadReaderQP m where
    asksQP :: (QueryParam -> a) -> m a

instance Monad m => MonadReaderQP (ContextT m) where
    asksQP = lift . asks
    {-# INLINEABLE asksQP #-}

instance MonadReaderQP DNSQuery where
    asksQP = lift . asksQP
    {-# INLINEABLE asksQP #-}

class Monad m => MonadReaderQS m where
    asksQS :: (QueryState -> a) -> m a

instance Monad m => MonadReaderQS (ContextT m) where
    asksQS = lift . lift . asks
    {-# INLINEABLE asksQS #-}

instance MonadReaderQS DNSQuery where
    asksQS = lift . asksQS
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
handleResponseError addrs e f msg = exerror $ \ee -> e $ ExtraError ee addrs msg
  where
    exerror eh
        | not (DNS.isResponse $ DNS.flags msg)              = eh   ErrorNotResp
        | DNS.ednsHeader msg == DNS.InvalidEDNS             = eh $ ErrorEDNS $ DNS.ednsHeader msg
        | DNS.rcode msg `notElem` [DNS.NoErr, DNS.NameErr]  = eh $ ErrorRCODE $ DNS.rcode msg
        | otherwise                                         = f msg
{- FOURMOLU_ENABLE -}

----------
-- Delegation

{- FOURMOLU_DISABLE -}
-- | The cases that generate `NotFilled`
data CasesNotFilledDS
    = CachedDelegation  {- intermediate state of reconstructing delegation-info using cache -}
    | ServsChildZone    {- when child(sub-domain) zone shares same authoritative server,
                            delegation-info that should contain DS records is not returned -}
    deriving Show

data MayFilledDS
    = NotFilledDS CasesNotFilledDS
    | FilledDS [RD_DS]                        {- Filled [] - DS does not exist | Filled (_:_) - DS exist, include DS only anchor -}
    | AnchorSEP [RD_DS] (NonEmpty RD_DNSKEY)  {- with specified trust-anchor dnskey -}
    deriving (Show)

data DFreshState
    = FreshD   {- Got from authoritative server directly -}
    | CachedD  {- From cache -}
    deriving Show
{- FOURMOLU_ENABLE -}

type Address = (IP, PortNumber)

-- | Delegation information for domain
data Delegation = Delegation
    { delegationZone :: Domain
    -- ^ Destination zone domain
    , delegationNS :: NonEmpty DEntry
    -- ^ NS infos of destination zone, get from source zone NS
    , delegationDS :: MayFilledDS
    -- ^ SEP DNSKEY signature of destination zone, get from source zone NS
    , delegationDNSKEY :: [RD_DNSKEY]
    -- ^ Destination DNSKEY set, get from destination NS
    , delegationFresh :: DFreshState
    -- ^ Fresh or Cached
    }
    deriving (Show)

{- FOURMOLU_DISABLE -}
chainedStateDS :: Delegation -> Bool
chainedStateDS d = case delegationDS d of
    NotFilledDS _     -> False
    FilledDS []       -> False
    FilledDS (_ : _)  -> True
    AnchorSEP {}      -> True
{- FOURMOLU_ENABLE -}

data DEntry
    = DEwithAx !Domain !(NonEmpty IPv4) !(NonEmpty IPv6)
    | DEwithA4 !Domain !(NonEmpty IPv4)
    | DEwithA6 !Domain !(NonEmpty IPv6)
    | DEonlyNS !Domain
    | DEstubA4 !(NonEmpty (IPv4, PortNumber))
    | DEstubA6 !(NonEmpty (IPv6, PortNumber))
    deriving (Show)

----------
-- DNSSEC Verification state and RRset

{- FOURMOLU_DISABLE -}
data MayVerifiedRRS
    = NotValidRRS CasesNotValid  {- not verified or invalid -}
    | ValidRRS [RD_RRSIG]        {- any RRSIG is passed. [RD_RRSIG] should be not null -}
    deriving Eq

data CasesNotValid
    = NV_NoSig                   {- request RRSIG, but not returned -}
    | NV_CheckDisabled           {- only for check-disabled state, so unknown whether verifiable or not. may verify again -}
    | NV_Invalid String          {- RRSIG exists, but no good RRSIG is found -}
    deriving (Eq, Show)

notValidNoSig :: MayVerifiedRRS
notValidNoSig = NotValidRRS NV_NoSig

notValidCheckDisabled :: MayVerifiedRRS
notValidCheckDisabled = NotValidRRS NV_CheckDisabled

notValidInvalid :: String -> MayVerifiedRRS
notValidInvalid = NotValidRRS . NV_Invalid

instance Show MayVerifiedRRS where
  show = mayVerifiedRRS "NotValidRRS NoSig" "NotValidRRS CheckDisabled" ("NotValidRRS_Invalid " ++) (("ValidRRS " ++) . show)

mayVerifiedRRS :: a -> a -> (String -> a) -> ([RD_RRSIG] -> a) -> MayVerifiedRRS -> a
mayVerifiedRRS noSig checkDisabled invalid valid m = case m of
    NotValidRRS  NV_NoSig           ->  noSig
    NotValidRRS  NV_CheckDisabled   ->  checkDisabled
    NotValidRRS (NV_Invalid es)     ->  invalid es
    ValidRRS sigs                   ->  valid sigs
{- FOURMOLU_ENABLE -}

data RRset = RRset
    { rrsName :: Domain
    , rrsType :: TYPE
    , rrsClass :: CLASS
    , rrsTTL :: TTL
    , rrsRDatas :: [RData]
    , rrsMayVerified :: MayVerifiedRRS
    }
    deriving (Show)

----------
-- alias

type RR = ResourceRecord

----------
-- results

{- response code, answer section, authority section -}
type Result = (RCODE, DNSFlags, [RR], [RR])
type ResultRRS' a = (a, [RRset], [RRset])
type ResultRRS = ResultRRS' RCODE
