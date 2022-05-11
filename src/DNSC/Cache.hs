{-# LANGUAGE StrictData #-}

module DNSC.Cache (
  -- * cache interfaces
  empty,
  lookup,
  takeRRSet,
  insert,
  expires,
  size,

  Ranking (..),
  rankedAnswer, rankedAuthority, rankedAdditional,

  insertSetFromSection,
  -- * types
  CDomain,
  CMailbox,
  CTxt,

  -- * handy interface
  insertRRs,

  -- * low-level interfaces
  Cache (..), Key (..), Val (..), CRSet (..),
  extractRRSet,
  (<+), alive,
  member,
  dump, dumpKeys,
  ) where

-- GHC packages
import Prelude hiding (lookup)
import Control.Monad (guard)
import Data.Function (on)
import Data.Maybe (isJust)
import Data.Either (partitionEithers)
import Data.List (group, groupBy, sortOn, uncons)
import Data.Int (Int64)
import Data.Word (Word16, Word32)
import Data.ByteString.Short (ShortByteString, toShort, fromShort)

-- dns packages
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ
import Data.IP (IPv4, IPv6)
import Network.DNS
  (Domain, CLASS, TTL, TYPE (..), RData (..),
   ResourceRecord (ResourceRecord), DNSMessage)
import qualified Network.DNS as DNS

-- this package
import DNSC.Types (Timestamp)

---

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

---

-- Ranking data (section 5.4.1 of RFC2181 - Clarifications to the DNS Specification)
-- <https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1>

data Ranking
{- + Additional information from an authoritative answer,
     Data from the authority section of a non-authoritative answer,
     Additional information from non-authoritative answers. -}
  = RankAdditional
{- + Data from the answer section of a non-authoritative answer, and
     non-authoritative data from the answer section of authoritative
     answers, -}
  | RankAnswer
{- + Glue from a primary zone, or glue from a zone transfer, -}
  --
{- + Data from the authority section of an authoritative answer, -}
  -- -- avoiding issue of authority section in reply with aa flag
{- + The authoritative data included in the answer section of an
     authoritative reply. -}
  | RankAuthAnswer
{- + Data from a zone transfer, other than glue, -}
  --
{- + Data from a primary zone file, other than glue data, -}
  --
  deriving (Eq, Ord, Show)
  -- ranking, derived order, the lower the beter

rankedSection :: Maybe Ranking -> Maybe Ranking -> (DNSMessage -> [ResourceRecord])
              -> DNSMessage -> Maybe ([ResourceRecord], Ranking)
rankedSection authRank noauthRank section msg =
  (,) (section msg)
  <$> if DNS.authAnswer flags then authRank else noauthRank
  where
    flags = DNS.flags $ DNS.header msg

rankedAnswer :: DNSMessage -> Maybe ([ResourceRecord], Ranking)
rankedAnswer =
  rankedSection
  (Just RankAuthAnswer)
  (Just RankAnswer)
  DNS.answer

rankedAuthority :: DNSMessage -> Maybe ([ResourceRecord], Ranking)
rankedAuthority =
  rankedSection
  Nothing  -- avoid security hole with authorized reply and authority section case
  (Just RankAdditional)
  DNS.authority

rankedAdditional :: DNSMessage -> Maybe ([ResourceRecord], Ranking)
rankedAdditional =
  rankedSection
  (Just RankAdditional)
  (Just RankAdditional)
  DNS.additional

---

data Key = Key CDomain TYPE CLASS deriving (Eq, Ord, Show)
data Val = Val CRSet Ranking deriving Show

data Cache = Cache (OrdPSQ Key Timestamp Val) Int {- max size -}

empty :: Int -> Cache
empty = Cache PSQ.empty

lookup :: Timestamp
       -> Domain -> TYPE -> CLASS
       -> Cache -> Maybe ([ResourceRecord], Ranking)
lookup now dom = lookup_ now result (fromDomain dom)
  where
    result k ttl (Val crs rank) = (extractRRSet k ttl crs, rank)

lookup_ :: Timestamp -> (Key -> TTL -> Val -> a)
        -> CDomain -> TYPE -> CLASS
        -> Cache -> Maybe a
lookup_ now mk dom typ cls (Cache cache _) = do
  let k = Key dom typ cls
  (eol, v) <- k `PSQ.lookup` cache
  ttl <- alive now eol
  return $ mk k ttl v

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
insert now k@(Key dom typ cls) ttl crs rank cache@(Cache c xsz) =
  maybe sized withOldRank lookupRank
  where
    lookupRank =
      lookup_ now (\_ _ (Val _ r) -> r)
      dom typ cls cache
    withOldRank r = do
      guard $ rank > r
      sized
    eol = now <+ ttl
    sized
      | PSQ.size inserted <= xsz  =  return $ Cache inserted xsz
      | otherwise                 =  do
          (_, _, _, deleted) <- PSQ.minView inserted
          return $ Cache deleted xsz
    inserted = PSQ.insert k eol (Val crs rank) c


expires :: Timestamp -> Cache -> Maybe Cache
expires now (Cache c xsz)
  | null exs   =  Nothing
  | otherwise  =  Just $ Cache result xsz
  where
    (exs, result) = PSQ.atMostView now c

alive :: Timestamp -> Timestamp -> Maybe TTL
alive now eol = do
  let ttl' = eol - now
      safeToTTL :: Int64 -> Maybe TTL
      safeToTTL sec = do
        let y = fromIntegral sec
        guard $ toInteger y == toInteger sec
        return y
  guard $ ttl' >= 1
  safeToTTL ttl'

size :: Cache -> Int
size (Cache c _) = PSQ.size c

---
{- debug interfaces -}

member :: Timestamp
       -> CDomain -> TYPE -> CLASS
       -> Cache -> Bool
member now dom typ cls = isJust . lookup_ now (\_ _ _ -> ()) dom typ cls

dump :: Cache -> [(Key, (Timestamp, Val))]
dump (Cache c _) = [ (k, (eol, v)) | (k, eol, v) <- PSQ.toAscList c ]

dumpKeys :: Cache -> [(Key, Timestamp)]
dumpKeys (Cache c _) = [ (k, eol) | (k, eol, _v) <- PSQ.toAscList c ]

---

(<+) :: Timestamp -> TTL -> Timestamp
now <+ ttl = now + fromIntegral ttl

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
    rdTYPE rd == Just rrtype  =  Just (Key (fromDomain rrname) rrtype rrclass, rrttl)
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
extractRRSet (Key dom ty cls) ttl = map (ResourceRecord (toDomain dom) ty cls ttl) . toRDatas

insertSetFromSection :: [ResourceRecord] -> Ranking -> ([[ResourceRecord]], [(((Key, TTL), CRSet), Ranking)])
insertSetFromSection rs0 r0 = (errRS, iset rrss r0)
  where
    key rr = (DNS.rrname rr, DNS.rrtype rr, DNS.rrclass rr)
    getRRSet rs = maybe (Left rs) Right $ takeRRSet rs
    (errRS, rrss) = partitionEithers . map getRRSet . groupBy ((==) `on` key) . sortOn key $ rs0
    iset ss rank = [ (rrset, rank) | rrset <- ss]
