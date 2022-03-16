{-# LANGUAGE StrictData #-}

module DNSC.Cache (
  -- * cache interfaces
  empty,
  lookup,
  takeRRSet,
  insert,
  expires,
  size,
  Timestamp,

  -- * handy interface
  insertRRs,

  -- * low-level interfaces
  Cache (Cache), Key (K), Val (V), CRSet (..),
  extractRRSet,
  queueSize, (<+), alive,
  expire1, member,
  dump, consistent,
  dumpKeys, minKey,
  ) where

import Prelude hiding (lookup)
import Control.Monad (guard)
import Data.Maybe (isJust, catMaybes)
import Data.List (group, uncons)
import Data.Word (Word16, Word32)
import Data.ByteString.Short (ShortByteString, toShort, fromShort)
import Data.Time (UTCTime, addUTCTime, diffUTCTime)
import Data.Map (Map)
import qualified Data.Map.Strict as Map

import Data.PSQueue (Binding ((:->)), PSQ)
import qualified Data.PSQueue as PSQ
import Data.IP (IPv4, IPv6)
import Network.DNS (Domain, CLASS, TTL, TYPE (..), RData (..), ResourceRecord (ResourceRecord))
import qualified Network.DNS as DNS


type CDomain = ShortByteString
type CMailbox = ShortByteString
type CTxt = ShortByteString

data CRSet
  = CR_A [IPv4]
  | CR_NS [CDomain]
  | CR_CNAME CDomain
  | CR_SOA CDomain CMailbox
    Word32 Word32 Word32 Word32 Word32
  | CR_PTR [CDomain]
  | CR_MX [(Word16, CDomain)]
  | CR_TXT [CTxt]
  | CR_AAAA [IPv6]
  deriving (Eq, Ord, Show)

type Ranking = ()

data Key = K CDomain TYPE CLASS deriving (Eq, Ord, Show)
data Val = V CRSet Ranking deriving Show

type Timestamp = UTCTime

data Cache = Cache (PSQ Key Timestamp) (Map Key Val) deriving Show

empty :: Cache
empty = Cache PSQ.empty Map.empty

lookup :: Timestamp
       -> Domain -> TYPE -> CLASS
       -> Cache -> Maybe ([ResourceRecord], Ranking)
lookup now dom = lookup_ now result (fromDomain dom)
  where
    result k ttl (V crs rank) = (extractRRSet k ttl crs, rank)

lookup_ :: Timestamp -> (Key -> TTL -> Val -> a)
        -> CDomain -> TYPE -> CLASS
        -> Cache -> Maybe a
lookup_ now mk dom typ cls (Cache lifetimes crss) = do
  let k = K dom typ cls
  eol <- k `PSQ.lookup` lifetimes
  ttl <- alive now eol
  rds <- k `Map.lookup` crss
  return $ mk k ttl rds

insertRRs :: Timestamp -> [ResourceRecord] -> Ranking -> Cache -> Maybe Cache
insertRRs now rrs rank c = insertRRSet =<< takeRRSet rrs
  where
    insertRRSet rrset = uncurry (uncurry $ insert now) rrset rank c

{- |
  Insert RR-list example with error-handling

@
   case takeRRSet rrList of  -- take RRSet with error-handling
     Nothing  ->  ...        -- inconsistent RR-list error
     Just rrset  ->
       maybe
       ( ... )   -- no update
       ( ... )   -- update with new-cache
       $ uncurry (uncurry $ insert now) rrset ranking cache
@
 -}
insert :: Timestamp -> Key -> TTL -> CRSet -> Ranking -> Cache -> Maybe Cache
insert now k ttl crs rank (Cache lifetimes vals) =
  Just $
  Cache
  (PSQ.insert k eol lifetimes)
  (Map.insert k (V crs rank) vals)
  where
    eol = now <+ ttl

expires :: Timestamp -> Cache -> Maybe Cache
expires now = rec0
  where
    rec0 c = rec1 <$> expire1 now c
    rec1 c = maybe c rec1 $ expire1 now c

expire1 :: Timestamp -> Cache -> Maybe Cache
expire1 now (Cache lifetimes crss) =
  uncurry ex =<< PSQ.minView lifetimes
  where
    ex (k :-> eol) lifetimes'
      | Just {} <- alive now eol  =  Nothing
      | otherwise                 =  Just $ Cache lifetimes' $ Map.delete k crss

alive :: Timestamp -> Timestamp -> Maybe TTL
alive now eol = do
  let ttl' = eol `diffUTCTime` now
  guard $ ttl' >= 1  -- TTL が Word32 なので、負のときに floor すると underflow してしまう
  return $ floor ttl'

size :: Cache -> Int
size (Cache _ crss) = Map.size crss

---
{- debug interfaces -}

queueSize :: Cache -> Int
queueSize (Cache lifetimes _) = PSQ.size lifetimes

member :: Timestamp
       -> CDomain -> TYPE -> CLASS
       -> Cache -> Bool
member now dom typ cls = isJust . lookup_ now (\_ _ _ -> ()) dom typ cls

dump :: Cache -> [(Key, (Timestamp, Val))]
dump (Cache lifetimes vals) =
  catMaybes $ zipWith op (PSQ.toAscList lifetimes) (Map.toAscList vals)
  where
    op (lk :-> eol) (k, v)
      | lk == k    =  Just (k, (eol, v))
      | otherwise  =  Nothing

consistent :: Cache -> Bool
consistent cache = queueSize cache == sz && length (dump cache) == sz
  where sz = size cache

dumpKeys :: Cache -> [(Key, Timestamp)]
dumpKeys (Cache lifetimes _) = map unBinding $ PSQ.toAscList lifetimes
  where
    unBinding (k :-> eol) = (k, eol)

minKey :: Cache -> Maybe (Key, Timestamp)
minKey = fmap fst . uncons . dumpKeys

---

(<+) :: Timestamp -> TTL -> Timestamp
now <+ ttl = fromIntegral ttl `addUTCTime` now

infixl 6 <+

toDomain :: CDomain -> DNS.Domain
toDomain = fromShort

fromDomain :: DNS.Domain -> CDomain
fromDomain = toShort

toRDatas :: CRSet -> [RData]
toRDatas crs = case crs of
  CR_A as     ->  map RD_A as
  CR_NS ds    ->  map (RD_NS . toDomain) ds
  CR_CNAME d  -> [RD_CNAME $ toDomain d]
  CR_SOA dom m a b c d e -> [RD_SOA (toDomain dom) (fromShort m) a b c d e]
  CR_PTR ds   ->  map (RD_PTR . toDomain) ds
  CR_MX ps    ->  map (\(w, d) -> RD_MX w $ toDomain d) ps
  CR_TXT ts   ->  map (RD_TXT . fromShort) ts
  CR_AAAA as  ->  map RD_AAAA as

fromRDatas :: [RData] -> Maybe CRSet
fromRDatas []    = Nothing
fromRDatas rds@(x:xs) = case x of
  RD_A {}     ->  Just $ CR_A [ a | RD_A a <- rds ]
  RD_NS {}    ->  Just $ CR_NS [ fromDomain d | RD_NS d <- rds ]
  RD_CNAME d
    | null xs   ->  Just $ CR_CNAME (fromDomain d)
    | otherwise ->  Nothing
  RD_SOA dom m a b c d e
    | null xs   ->  Just $ CR_SOA (fromDomain dom) (toShort m) a b c d e
    | otherwise ->  Nothing
  RD_PTR {}   ->  Just $ CR_PTR [ fromDomain d | RD_PTR d <- rds ]
  RD_MX {}    ->  Just $ CR_MX [ (w, fromDomain d) | RD_MX w d <- rds ]
  RD_TXT {}   ->  Just $ CR_TXT [ toShort t | RD_TXT t <- rds ]
  RD_AAAA {}  ->  Just $ CR_AAAA [ a | RD_AAAA a <- rds ]
  _           ->  Nothing

rdTYPE :: RData -> Maybe TYPE
rdTYPE cr = case cr of
  RD_A {}      ->  Just A
  RD_NS {}     ->  Just NS
  RD_CNAME {}  ->  Just CNAME
  RD_SOA {}    ->  Just SOA
  RD_PTR {}    ->  Just PTR
  RD_MX {}     ->  Just MX
  RD_TXT {}    ->  Just TXT
  RD_AAAA {}   ->  Just AAAA
  _            ->  Nothing

rrSetKey :: ResourceRecord -> Maybe (Key, TTL)
rrSetKey (ResourceRecord rrname rrtype rrclass rrttl rd)
  | rrclass == DNS.classIN &&
    rdTYPE rd == Just rrtype  =  Just (K (fromDomain rrname) rrtype rrclass, rrttl)
  | otherwise                 =  Nothing

takeRRSet :: [ResourceRecord] -> Maybe ((Key, TTL), CRSet)
takeRRSet []        =    Nothing
takeRRSet rrs@(_:_) = do
  ps <- mapM rrSetKey rrs         -- それぞれ RR で、rrtype と rdata が整合している
  guard $ length (group ps) == 1  -- query のキーと TTL がすべて一致
  (k', _) <- uncons ps            -- rrs が空でないので必ず成功するはず
  rds <- fromRDatas $ map DNS.rdata rrs
  return (k', rds)

extractRRSet :: Key -> TTL -> CRSet -> [ResourceRecord]
extractRRSet (K dom ty cls) ttl = map (ResourceRecord (toDomain dom) ty cls ttl) . toRDatas
