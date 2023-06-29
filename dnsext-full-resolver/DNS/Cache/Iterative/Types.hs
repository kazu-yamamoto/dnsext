module DNS.Cache.Iterative.Types (
    UpdateCache,
    TimeCache,
    Result,
    Env (..),
    RRset (..),
    DEntry (..),
    ContextT,
    Delegation (..),
    QueryError (..),
    DNSQuery,
    runDNSQuery,
) where

import Control.Monad.Trans.Except (ExceptT (..), runExceptT)
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
    , disableV6NS_ :: Bool
    , insert_ :: Key -> TTL -> CRSet -> Ranking -> IO ()
    , getCache_ :: IO Cache
    , expireCache :: EpochTime -> IO ()
    , currentRoot_ :: IORef (Maybe Delegation)
    , currentSeconds_ :: IO EpochTime
    , timeString_ :: IO ShowS
    , idGen_ :: IO DNS.Identifier
    }

-- | Delegation information for domain
data Delegation = Delegation
    { delegationZone :: Domain
    -- ^ Destination zone domain
    , delegationNS :: NE DEntry
    -- ^ NS infos of destination zone, get from source zone NS
    , delegationDS :: [RD_DS]
    -- ^ SEP DNSKEY signature of destination zone, get from source zone NS
    , delegationDNSKEY :: [RD_DNSKEY]
    -- ^ Destination DNSKEY set, get from destination NS
    }
    deriving (Show)

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
