module DNS.Cache.Iterative.Types (
    UpdateCache,
    TimeCache,
    Result,
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
    runDNSQuery,
    throwDnsError,
) where

import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Control.Monad.Trans.Reader (ReaderT (..))
import Data.IORef (IORef)
import Data.IP (IP)

import DNS.Cache.Types (NE)
import DNS.Do53.Client (
    QueryControls (..),
 )
import DNS.Do53.Memo (
    CRSet,
    Cache,
    Key,
    Ranking,
 )
import qualified DNS.Log as Log
import DNS.SEC (
    RD_DNSKEY,
    RD_DS (..),
    RD_RRSIG (..),
    TYPE,
 )
import DNS.Types (
    CLASS,
    DNSError,
    DNSMessage,
    Domain,
    RCODE,
    RData,
    ResourceRecord (..),
    TTL,
 )
import qualified DNS.Types as DNS
import DNS.Types.Decode (EpochTime)

type UpdateCache =
    ( Key -> TTL -> CRSet -> Ranking -> IO ()
    , IO Cache
    , EpochTime -> IO ()
    )

type TimeCache = (IO EpochTime, IO ShowS)

data Env = Env
    { logLines_ :: Log.PutLines
    , logQSize_ :: Log.GetQueueSize
    , logTerminate_ :: Log.Terminate
    , disableV6NS_ :: Bool
    , insert_ :: Key -> TTL -> CRSet -> Ranking -> IO ()
    , getCache_ :: IO Cache
    , expireCache :: EpochTime -> IO ()
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
{- FOURMOLU_ENABLE -}

-- | Delegation information for domain
data Delegation = Delegation
    { delegationZone :: Domain
    -- ^ Destination zone domain
    , delegationNS :: NE DEntry
    -- ^ NS infos of destination zone, get from source zone NS
    , delegationDS :: MayFilledDS
    -- ^ SEP DNSKEY signature of destination zone, get from source zone NS
    , delegationDNSKEY :: [RD_DNSKEY]
    -- ^ Destination DNSKEY set, get from destination NS
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

data RRset = RRset
    { rrsName :: Domain
    , rrsType :: TYPE
    , rrsClass :: CLASS
    , rrsTTL :: TTL
    , rrsRDatas :: [RData]
    , rrsGoodSigs :: [RD_RRSIG]
    }
    deriving (Show)

{- response code, answer section, authority section -}
type Result = (RCODE, [ResourceRecord], [ResourceRecord])
