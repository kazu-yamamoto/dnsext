{-# LANGUAGE FlexibleContexts #-}

module DNS.Iterative.Query.Class (
    MonadEnv (..),
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
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.Int (Int64)
import Data.IP (IP, IPv4, IPv6)
import Network.Socket (PortNumber)
import Data.Map.Strict (Map)

-- dnsext packages
import DNS.Do53.Client (Reply)
import qualified DNS.Log as Log
import DNS.RRCache (Cache, Ranking)
import qualified DNS.RRCache as Cache
import DNS.SEC (RD_DNSKEY, RD_DS, RD_RRSIG)
import qualified DNS.TAP.Schema as DNSTAP
import DNS.Types hiding (flags)
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Stats (Stats)

----------
-- tagless-final effect interfaces

class (MonadReader Env m, MonadIO m) => MonadEnv m where
    asksEnv :: (Env -> a) -> m a

----------

class Monad m => MonadReaderQP m where
    asksQP :: (QueryParam -> a) -> m a

----------

class Monad m => MonadReaderQS m where
    asksQS :: (QueryState -> a) -> m a

setQS :: (MonadReaderQS m, MonadIO m) => (QueryState -> StateVal a n) -> a -> m ()
setQS f x = do
    StateVal ref <- asksQS f
    liftIO $ atomicModifyIORef' ref (\_ -> (x, ()))

getQS :: (MonadReaderQS m, MonadIO m) => (QueryState -> StateVal a n) -> m a
getQS f = do
    StateVal ref <- asksQS f
    liftIO $ readIORef ref

----------
-- Env context type for Monad

data Env = Env
    { shortLog_ :: Bool
    , logLines_ :: Log.PutLines IO
    , logDNSTAP_ :: DNSTAP.Message -> IO ()
    , disableV6NS_ :: Bool
    , rootAnchor_ :: MayFilledDS
    , rootHint_ :: Delegation
    , chaosZones_ :: LocalZones
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
    , reloadInfo_ :: [(String, IO Int64)]
    , statsInfo_ :: [(String, String)]
    , stats_ :: Stats
    , nsid_ :: Maybe OD_NSID
    , updateHistogram_ :: Integer -> Stats -> IO ()
    , timeout_ :: IO Reply -> IO (Maybe Reply)
    }

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
-- DNSSEC Verification state and RRset

{- FOURMOLU_DISABLE -}
data MayVerifiedRRS
    = NotValidRRS CasesNotValid  {- not verified or invalid -}
    | ValidRRS [RD_RRSIG]        {- any RRSIG is passed. [RD_RRSIG] should be not null -}
    deriving Eq

mayVerifiedRRS :: a -> a -> (String -> a) -> ([RD_RRSIG] -> a) -> MayVerifiedRRS -> a
mayVerifiedRRS noSig checkDisabled invalid valid m = case m of
    NotValidRRS  NV_NoSig           ->  noSig
    NotValidRRS  NV_CheckDisabled   ->  checkDisabled
    NotValidRRS (NV_Invalid es)     ->  invalid es
    ValidRRS sigs                   ->  valid sigs

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

data DEntry
    = DEwithAx !Domain !(NonEmpty IPv4) !(NonEmpty IPv6)
    | DEwithA4 !Domain !(NonEmpty IPv4)
    | DEwithA6 !Domain !(NonEmpty IPv6)
    | DEonlyNS !Domain
    | DEstubA4 !(NonEmpty (IPv4, PortNumber))
    | DEstubA6 !(NonEmpty (IPv6, PortNumber))
    deriving (Show)

----------
-- QueryParam context type for Monad

data QueryParam = QueryParam
    { origQuestion_ :: Question
    , requestDO_ :: RequestDO
    , requestCD_ :: RequestCD
    , requestAD_ :: RequestAD
    }

queryParamH :: Question -> DNSFlags -> EDNSheader -> QueryParam
queryParamH q flags eh = QueryParam q (toRequestDO eh) (toRequestCD flags) (toRequestAD flags)

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

toRequestDO :: EDNSheader -> RequestDO
toRequestDO = ednsHeaderCases (bool NoDnssecOK DnssecOK . ednsDnssecOk) NoDnssecOK NoDnssecOK

toRequestCD :: DNSFlags -> RequestCD
toRequestCD = bool NoCheckDisabled CheckDisabled . chkDisable

toRequestAD :: DNSFlags -> RequestAD
toRequestAD = bool NoAuthenticatedData AuthenticatedData . authenData

----------
-- fold EDNS

{- FOURMOLU_DISABLE -}
ednsHeaderCases :: (EDNS -> a) -> a -> a -> EDNSheader -> a
ednsHeaderCases heh noh inv eh = case eh of
    EDNSheader edns  -> heh edns
    NoEDNS           -> noh
    InvalidEDNS      -> inv
{- FOURMOLU_ENABLE -}

----------
-- QueryState context type for Monad

data QueryCount
data LastQuery
data AservMessage
newtype StateVal a n = StateVal (IORef a)

{- FOURMOLU_DISABLE -}
data QueryState = QueryState
    { queryCounter_  :: StateVal Int QueryCount
    , lastQuery_     :: StateVal (Question, [Address]) LastQuery
    , aservMessage_  :: StateVal (Maybe DNSMessage) AservMessage
    }
{- FOURMOLU_ENABLE -}

newStateVal :: a -> IO (StateVal a n)
newStateVal iv = StateVal <$> newIORef iv

newQueryState :: IO QueryState
newQueryState = do
    refq <- newStateVal 0
    rlsq <- newStateVal (Question (fromString "") A IN, [])
    rasm <- newStateVal Nothing
    pure $ QueryState refq rlsq rasm
