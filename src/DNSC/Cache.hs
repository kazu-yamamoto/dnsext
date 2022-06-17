{-# LANGUAGE StrictData #-}

module DNSC.Cache (
  -- * cache interfaces
  empty,
  lookup, lookupEither,
  takeRRSet,
  insert,
  expires,
  size,

  Ranking (..),
  rankedAnswer, rankedAuthority, rankedAdditional,

  insertSetFromSection,
  insertSetEmpty,

  nxTYPE,
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
import Control.DeepSeq (deepseq, liftRnf)
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
  | CR_EMPTY CDomain {- NXDOMAIN or NODATA, hold domain delegatoin from -}
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

rankedSection :: Ranking -> Ranking -> (DNSMessage -> [ResourceRecord])
              -> DNSMessage -> ([ResourceRecord], Ranking)
rankedSection authRank noauthRank section msg =
  (,) (section msg)
  $ if DNS.authAnswer flags then authRank else noauthRank
  where
    flags = DNS.flags $ DNS.header msg

rankedAnswer :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAnswer =
  rankedSection
  RankAuthAnswer
  RankAnswer
  DNS.answer

rankedAuthority :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAuthority =
  rankedSection
  {- avoid security hole with authorized reply and authority section case.
     RankAdditional does not overwrite glue. -}
  RankAdditional
  RankAdditional
  DNS.authority

rankedAdditional :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAdditional =
  rankedSection
  RankAdditional
  RankAdditional
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
lookup now dom typ cls = lookup_ now result (fromDomain dom) typ cls
  where
    result ttl (Val crs rank) = Just (extractRRSet dom typ cls ttl crs, rank)

-- when cache has EMPTY, returns SOA
lookupEither :: Timestamp
             -> Domain -> TYPE -> CLASS
             -> Cache -> Maybe (Either ([ResourceRecord], Ranking) [ResourceRecord], Ranking)  {- SOA or RRs, ranking -}
lookupEither now dom typ cls cache = lookup_ now result (fromDomain dom) typ cls cache
  where
    result ttl (Val crs rank) = case crs of
      CR_EMPTY srcDom  ->  do
        sp <- lookup_ now (soaResult $ toDomain srcDom) srcDom SOA DNS.classIN cache  {- EMPTY hit. empty ranking and SOA result. -}
        return (Left sp, rank)
      _                ->  Just (Right $ extractRRSet dom typ DNS.classIN ttl crs, rank)
    soaResult srcDom ttl (Val crs rank) = Just (extractRRSet srcDom SOA DNS.classIN ttl crs, rank)

lookup_ :: Timestamp -> (TTL -> Val -> Maybe a)
        -> CDomain -> TYPE -> CLASS
        -> Cache -> Maybe a
lookup_ now mk dom typ cls (Cache cache _) = do
  let k = Key dom typ cls
  (eol, v) <- k `PSQ.lookup` cache
  ttl <- alive now eol
  mk ttl v

insertRRs :: Timestamp -> [ResourceRecord] -> Ranking -> Cache -> Maybe Cache
insertRRs now rrs rank c = insertRRSet =<< takeRRSet rrs
  where
    insertRRSet rrset = rrset $ \key ttl cr -> insert now key ttl cr rank c

{- |
  Insert RR-list example with error-handling

@
   case insertSetFromSection rrList rank of
     (errRRLists, rrsets) ->
       ...
       [ k (insert now) cache  -- insert Maybe action
       | k <- rrsets
       ]
       ...
       ... errRRLists ...  -- error handlings
@

  Insert empty-RRSet example for negative cache
@
   insertSetEmpty sdom dom typ ttl rank (insert now) cache  -- insert Maybe action
@
 -}
insert :: Timestamp -> Key -> TTL -> CRSet -> Ranking -> Cache -> Maybe Cache
insert now k@(Key dom typ cls) ttl crs rank cache@(Cache c xsz) =
  maybe sized withOldRank lookupRank
  where
    lookupRank =
      lookup_ now (\_ (Val _ r) -> Just r)
      dom typ cls cache
    withOldRank r = do
      guard $ rank > r
      inserted  -- replacing rank does not change size
    eol = now <+ ttl
    inserted = Just $ Cache (PSQ.insert k eol (Val crs rank) c) xsz
    sized
      | PSQ.size c < xsz  =  inserted
      | otherwise         =  do
          (_, l, _, deleted) <- PSQ.minView c
          guard $ eol > l  -- Guard if the tried to insert has the smallest lifetime
          Just $ Cache (PSQ.insert k eol (Val crs rank) deleted) xsz

expires :: Timestamp -> Cache -> Maybe Cache
expires now (Cache c xsz) =
  case PSQ.findMin c of
    Just (_, eol, _) | eol <= now ->  Just $ Cache (snd $ PSQ.atMostView now c) xsz
                     | otherwise  ->  Nothing
    Nothing                       ->  Nothing

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

-- code from Reserved for Private Use (section 3.1 of RFC6895)
-- <https://datatracker.ietf.org/doc/html/rfc6895#section-3.1>
nxTYPE :: TYPE
nxTYPE = DNS.toTYPE 0xff00

---
{- debug interfaces -}

member :: Timestamp
       -> CDomain -> TYPE -> CLASS
       -> Cache -> Bool
member now dom typ cls = isJust . lookup_ now (\_ _ -> Just ()) dom typ cls

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
  CR_EMPTY {} ->  []

fromRDatas :: [RData] -> Maybe CRSet
fromRDatas []    = Nothing
fromRDatas rds@(x:xs) = case x of
  -- seq CRSet data in cache to cut references to bytestrings
  RD_A {}     ->  let as = [ a | RD_A a <- rds ] in as `listseq` Just (CR_A as)
  RD_NS {}    ->  let ds = [ fromDomain d | RD_NS d <- rds ] in ds `deepseq` Just (CR_NS ds)
  RD_CNAME d
    | null xs   ->  let d' = fromDomain d in d' `seq` Just (CR_CNAME d')
    | otherwise ->  Nothing
  RD_SOA dom m a b c d e
    | null xs   ->  let { d' = fromDomain dom; m' = toShort m } in d' `seq` m' `seq`
                        Just (CR_SOA d' m' a b c d e)
    | otherwise ->  Nothing
  RD_PTR {}   ->  let ds = [ fromDomain d | RD_PTR d <- rds ] in ds `deepseq` Just (CR_PTR ds)
  RD_MX {}    ->  let ps = [ (w, fromDomain d) | RD_MX w d <- rds ] in ps `deepseq` Just (CR_MX ps)
  RD_TXT {}   ->  let ts = [ toShort t | RD_TXT t <- rds ] in ts `deepseq` Just (CR_TXT ts)
  RD_AAAA {}  ->  let as = [ a | RD_AAAA a <- rds ] in as `listseq` Just (CR_AAAA as)
  _           ->  Nothing
  where
    listRnf :: [a] -> ()
    listRnf = liftRnf (`seq` ())
    listseq :: [a] -> b -> b
    listseq ps q = case listRnf ps of () -> q

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

takeRRSet :: [ResourceRecord] -> Maybe ((Key -> TTL -> CRSet -> a) -> a)
takeRRSet []        =    Nothing
takeRRSet rrs@(_:_) = do
  ps <- mapM rrSetKey rrs         -- それぞれ RR で、rrtype と rdata が整合している
  guard $ length (group ps) == 1  -- query のキーと TTL がすべて一致
  (k', _) <- uncons ps            -- rrs が空でないので必ず成功するはず
  rds <- fromRDatas $ map DNS.rdata rrs
  return $ \h -> uncurry h k' rds

extractRRSet :: Domain -> TYPE -> CLASS -> TTL -> CRSet -> [ResourceRecord]
extractRRSet dom ty cls ttl = map (ResourceRecord dom ty cls ttl) . toRDatas

insertSetFromSection :: [ResourceRecord] -> Ranking -> ([[ResourceRecord]], [(Key -> TTL -> CRSet -> Ranking -> a) -> a])
insertSetFromSection rs0 r0 = (errRS, iset rrss r0)
  where
    key rr = (DNS.rrname rr, DNS.rrtype rr, DNS.rrclass rr)
    getRRSet rs = maybe (Left rs) Right $ takeRRSet rs
    (errRS, rrss) = partitionEithers . map getRRSet . groupBy ((==) `on` key) . sortOn key $ rs0
    iset ss rank = [ \h -> rrset $ \k ttl cr -> h k ttl cr rank | rrset <- ss]

insertSetEmpty :: Domain -> Domain -> TYPE -> TTL -> Ranking -> ((Key -> TTL -> CRSet -> Ranking -> a) -> a)
insertSetEmpty srcDom dom typ ttl rank h = h key ttl (CR_EMPTY $ fromDomain srcDom) rank
  where
    key = Key (fromDomain dom) typ DNS.classIN
