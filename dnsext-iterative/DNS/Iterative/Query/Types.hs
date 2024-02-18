module DNS.Iterative.Query.Types (
    Result,
    ResultRRS,
    LocalZoneType (..),
    Env (..),
    QueryContext (..),
    queryContextIN,
    RRset (..),
    DEntry (..),
    ContextT,
    CasesNotFilledDS (..),
    MayFilledDS (..),
    Delegation (..),
    delegationHasDS,
    QueryError (..),
    DNSQuery,
    MayVerifiedRRS (..),
    mayVerifiedRRS,
    DFreshState (..),
    runDNSQuery,
    throwDnsError,
    handleDnsError,
) where

-- GHC packages
import Data.IORef (IORef)

-- other packages

-- dnsext packages
import DNS.Do53.Client (QueryControls (..), Reply)
import qualified DNS.Log as Log
import DNS.RRCache (
    CRSet,
    Cache,
    Ranking,
 )
import DNS.SEC
import qualified DNS.TAP.Schema as DNSTAP
import DNS.Types
import qualified DNS.Types as DNS
import Data.IP (IP)

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

----------
-- Monad and context

data Env = Env
    { logLines_ :: Log.PutLines
    , logDNSTAP_ :: DNSTAP.Message -> IO ()
    , disableV6NS_ :: Bool
    , rootAnchor_ :: Maybe ([RD_DNSKEY], [RD_DS])
    , rootHint_ :: Delegation
    , lookupLocalApex_ :: Domain -> Maybe (Domain, LocalZoneType, [RRset])
    , lookupLocalDomain_ :: (Domain, LocalZoneType, [RRset]) -> Question -> Maybe ResultRRS
    , insert_ :: Question -> TTL -> CRSet -> Ranking -> IO ()
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
    { qcontrol_ :: QueryControls
    , origQuestion_ :: Question
    }

queryContextIN :: Domain -> TYPE -> QueryControls -> QueryContext
queryContextIN dom typ qctl = QueryContext qctl $ Question dom typ IN

data QueryError
    = DnsError DNSError
    | NotResponse Bool DNSMessage
    | InvalidEDNS DNS.EDNSheader DNSMessage
    | HasError DNS.RCODE DNSMessage
    | QueryDenied
    deriving (Show)

type ContextT m = ReaderT Env (ReaderT QueryContext m)
type DNSQuery = ExceptT QueryError (ContextT IO)

runDNSQuery :: DNSQuery a -> Env -> QueryContext -> IO (Either QueryError a)
runDNSQuery q = runReaderT . runReaderT (runExceptT q)

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwE . DnsError

handleDnsError
    :: (QueryError -> DNSQuery a)
    -> (a -> DNSQuery a)
    -> DNSQuery a
    -> DNSQuery a
handleDnsError left right q = either left right =<< lift (runExceptT q)

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
    | FilledDS [RD_DS]  {- Filled [] - confirmed DS does not exist | Filled (_:_) exist -}
    | FilledRoot
    deriving (Show)

data DFreshState
    = FreshD   {- Got from authoritative server directly -}
    | CachedD  {- From cache -}
    deriving Show
{- FOURMOLU_ENABLE -}

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

delegationHasDS :: Delegation -> Bool
delegationHasDS d = case delegationDS d of
    NotFilledDS _ -> False
    (FilledDS []) -> False
    (FilledDS (_ : _)) -> True
    FilledRoot -> True

data DEntry
    = DEwithAx !Domain !IP
    | DEonlyNS !Domain
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
type ResultRRS = (RCODE, [RRset], [RRset])
