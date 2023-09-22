module DNS.Iterative.Query.Types (
    Result,
    ResultRRS,
    Env (..),
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
    NonEmpty (..),
) where

-- GHC packages
import Data.IORef (IORef)

-- other packages
import Data.IP (IP)
import Data.List.NonEmpty (NonEmpty (..))

-- dnsext packages
import DNS.Do53.Client (QueryControls (..))
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

-- this package
import DNS.Iterative.Imports

data Env = Env
    { logLines_ :: Log.PutLines
    , logDNSTAP_ :: DNSTAP.Message -> IO ()
    , disableV6NS_ :: Bool
    , insert_ :: Question -> TTL -> CRSet -> Ranking -> IO ()
    , getCache_ :: IO Cache
    , expireCache_ :: EpochTime -> IO ()
    , currentRoot_ :: IORef (Maybe Delegation)
    , currentSeconds_ :: IO EpochTime
    , timeString_ :: IO ShowS
    , idGen_ :: IO DNS.Identifier
    }

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

data DEntry
    = DEwithAx !Domain !IP
    | DEonlyNS !Domain
    deriving (Show)

data QueryError
    = DnsError DNSError
    | NotResponse DNS.QorR DNSMessage
    | InvalidEDNS DNS.EDNSheader DNSMessage
    | HasError DNS.RCODE DNSMessage
    deriving (Show)

type ContextT m = ReaderT Env (ReaderT QueryControls m)
type DNSQuery = ExceptT QueryError (ContextT IO)

runDNSQuery
    :: DNSQuery a -> Env -> QueryControls -> IO (Either QueryError a)
runDNSQuery q = runReaderT . runReaderT (runExceptT q)

throwDnsError :: DNSError -> DNSQuery a
throwDnsError = throwE . DnsError

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

{- response code, answer section, authority section -}
type Result = (RCODE, [ResourceRecord], [ResourceRecord])
type ResultRRS = (RCODE, [RRset], [RRset])
