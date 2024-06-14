{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Types (
    Result,
    ResultRRS',
    ResultRRS,
    LocalZoneType (..),
    LocalZones,
    StubZones,
    Env (..),
    QueryContext (..),
    queryContext,
    queryContextIN,
    RequestDO (..),
    RequestCD (..),
    RequestAD (..),
    RRset (..),
    Address,
    DEntry (..),
    ContextT,
    CasesNotFilledDS (..),
    MayFilledDS (..),
    Delegation (..),
    chainedStateDS,
    QueryError (..),
    DNSQuery,
    MonadReaderQC (..),
    MayVerifiedRRS (..),
    mayVerifiedRRS,
    DFreshState (..),
    runDNSQuery,
    throwDnsError,
    handleDnsError,
    handleResponseError,
) where

-- GHC packages
import Data.IORef (IORef)
import Data.Map (Map)

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
    { logLines_ :: Log.PutLines
    , logDNSTAP_ :: DNSTAP.Message -> IO ()
    , disableV6NS_ :: Bool
    , rootAnchor_ :: MayFilledDS
    , rootHint_ :: Delegation
    , localZones_ :: LocalZones
    , stubZones_ :: StubZones
    , maxNegativeTTL_ :: TTL
    , insert_ :: Question -> TTL -> Cache.Hit -> Ranking -> IO ()
    , getCache_ :: IO Cache
    , expireCache_ :: EpochTime -> IO ()
    , currentRoot_ :: IORef (Maybe Delegation)
    , currentSeconds_ :: IO EpochTime
    , timeString_ :: IO ShowS
    , idGen_ :: IO DNS.Identifier
    , stats_ :: Stats
    , timeout_ :: IO Reply -> IO (Maybe Reply)
    }

data QueryContext = QueryContext
    { origQuestion_ :: Question
    , requestDO_ :: RequestDO
    , requestCD_ :: RequestCD
    , requestAD_ :: RequestAD
    }

queryContext :: Question -> QueryControls -> QueryContext
queryContext q qctl = QueryContext q (toRequestDO qctl) (toRequestCD qctl) (toRequestAD qctl)

queryContextIN :: Domain -> TYPE -> QueryControls -> QueryContext
queryContextIN dom typ qctl = queryContext (Question dom typ IN) qctl

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
    deriving (Show)

data RequestCD
    = CheckDisabled
    | NoCheckDisabled
    deriving (Show)

data RequestAD
    = AuthenticatedData
    | NoAuthenticatedData
    deriving (Show)

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

data QueryError
    = DnsError DNSError [String]
    | NotResponse Bool DNSMessage
    | InvalidEDNS DNS.EDNSheader DNSMessage
    | HasError DNS.RCODE DNSMessage
    | QueryDenied
    deriving (Show)

type ContextT m = ReaderT Env (ReaderT QueryContext m)
type DNSQuery = ExceptT QueryError (ContextT IO)

class MonadReaderQC m where
    asksQC :: (QueryContext -> a) -> m a

instance Monad m => MonadReaderQC (ContextT m) where
    asksQC = lift . asks
    {-# INLINEABLE asksQC #-}

instance MonadReaderQC DNSQuery where
    asksQC = lift . asksQC
    {-# INLINEABLE asksQC #-}

runDNSQuery :: DNSQuery a -> Env -> QueryContext -> IO (Either QueryError a)
runDNSQuery q = runReaderT . runReaderT (runExceptT q)

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwError . (`DnsError` [])

handleDnsError
    :: (QueryError -> DNSQuery a)
    -> (a -> DNSQuery a)
    -> DNSQuery a
    -> DNSQuery a
handleDnsError left right q = either left right =<< lift (runExceptT q)

-- example instances
-- - responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- - responseErrDNSQuery = handleResponseError throwError pure  :: DNSMessage -> DNSQuery DNSMessage
handleResponseError :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError e f msg
    | not (DNS.isResponse flags_) = e $ NotResponse (DNS.isResponse flags_) msg
    | DNS.ednsHeader msg == DNS.InvalidEDNS =
        e $ InvalidEDNS (DNS.ednsHeader msg) msg
    | DNS.rcode msg
        `notElem` [DNS.NoErr, DNS.NameErr] =
        e $ HasError (DNS.rcode msg) msg
    | otherwise = f msg
  where
    flags_ = DNS.flags msg

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
    = NotVerifiedRRS       {- not judged valid or invalid -}
    | InvalidRRS String    {- RRSIG found, but no RRSIG is passed -}
    | ValidRRS [RD_RRSIG]  {- any RRSIG is passed. [RD_RRSIG] should be not null -}
    deriving Eq

instance Show MayVerifiedRRS where
  show = mayVerifiedRRS "NotVerifiedRRS" ("InvalidRRS " ++) (("ValidRRS " ++) . show)

mayVerifiedRRS :: a -> (String -> a) -> ([RD_RRSIG] -> a) -> MayVerifiedRRS -> a
mayVerifiedRRS notVerified invalid valid m = case m of
    NotVerifiedRRS  ->  notVerified
    InvalidRRS es   ->  invalid es
    ValidRRS sigs   ->  valid sigs
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
-- results

{- response code, answer section, authority section -}
type Result = (RCODE, [ResourceRecord], [ResourceRecord])
type ResultRRS' a = (a, [RRset], [RRset])
type ResultRRS = ResultRRS' RCODE
