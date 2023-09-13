{-# LANGUAGE PatternSynonyms #-}

module DNS.Do53.RRCache.Types (
    -- * cache interfaces
    empty,
    null,
    lookupAlive,
    insert,
    expires,
    size,
    stubLookup,
    stubInsert,
    Ranking (..),
    rankedAnswer,
    rankedAuthority,
    rankedAdditional,
    insertSetFromSection,
    insertSetEmpty,
    TYPE (NX),

    -- * handy interface
    insertRRs,

    -- * low-level interfaces
    Cache (..),
    Question (..),
    Val (..),
    extractRRSet,
    (<+),
    alive,
    member,
    dump,
    dumpKeys,

    -- * low-level, cache entry
    Positive (..),
    positiveHit,
    positiveRDatas,
    positiveRRSIGs,
    Hit (..),
    hitEither,
    CRSet,
    mkNotVerified,
    notVerified,
    mkValid,
    valid,
    unCRSet,

    -- * tests
    lookup,
    lookupEither,
    takeRRSet,
)
where

-- GHC packages
import Control.DeepSeq (liftRnf)
import Control.Monad (guard)
import Data.Either (partitionEithers)
import Data.Function (on)
import Data.List (group, groupBy, sortOn, uncons)
import Data.Maybe (isJust)
import Prelude hiding (lookup, null)

-- others
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ

-- dnsext packages
import DNS.SEC (RD_RRSIG, TYPE (RRSIG))
import DNS.Types (
    CLASS,
    DNSMessage,
    Domain,
    Question (..),
    RData,
    ResourceRecord (ResourceRecord),
    TTL,
 )
import qualified DNS.Types as DNS
import DNS.Types.Decode (EpochTime)
import DNS.Types.Internal (TYPE (..))

---
data NE a = NE a [a] deriving (Eq)

neList :: NE a -> [a]
neList (NE x xs) = x : xs

cons1 :: [a] -> b -> (a -> [a] -> b) -> b
cons1 [] nil _ = nil
cons1 (x : xs) _ cons = cons x xs

instance Show a => Show (NE a) where
    show = show . neList

type RDatas = NE RData
type RRSIGs = NE RD_RRSIG

{- FOURMOLU_DISABLE -}
data Positive
    = NotVerified RDatas        {- not verified -}
    {-- | VerifyFailed RDatas   {- verification failed -} {- unused state -} --}
    | Valid RDatas RRSIGs       {- verification succeeded -}
    deriving (Eq, Show)

positiveHit :: ([RData] -> a) -> ([RData] -> [RD_RRSIG] -> a) -> Positive -> a
positiveHit notVerified_ valid_ pos = case pos of
    NotVerified rds -> notVerified_ $ neList rds
    Valid rds ss  -> valid_ (neList rds) (neList ss)

data Hit
    = Negative Domain           {- Negative hit, NXDOMAIN or NODATA, hold zone-domain delegation from -}
    | Positive Positive         {- Positive hit -}
    deriving (Eq, Show)

hitEither :: (Domain -> a) -> (Positive -> a) -> Hit -> a
hitEither negative positive hit = case hit of
    Negative soa -> negative soa
    Positive pos -> positive pos
{- FOURMOLU_ENABLE -}

type CRSet = Hit

mkNotVerified :: RData -> [RData] -> CRSet
mkNotVerified d ds = Positive $ NotVerified $ NE d ds

notVerified :: [RData] -> a -> (CRSet -> a) -> a
notVerified rds nothing just = cons1 rds nothing ((just .) . mkNotVerified)

mkValid :: RData -> [RData] -> RD_RRSIG -> [RD_RRSIG] -> CRSet
mkValid d ds s ss = Positive $ Valid (NE d ds) (NE s ss)

valid :: [RData] -> [RD_RRSIG] -> a -> (CRSet -> a) -> a
valid rds sigs nothing just = cons1 rds nothing withRds
  where
    withRds d ds = cons1 sigs nothing withSigs
      where
        withSigs s ss = just $ mkValid d ds s ss

unCRSet :: (Domain -> a) -> ([RData] -> a) -> ([RData] -> [RD_RRSIG] -> a) -> CRSet -> a
unCRSet negative notVerified_ valid_ = hitEither negative (positiveHit notVerified_ valid_)

positiveRDatas :: Positive -> [RData]
positiveRDatas = positiveHit id const

positiveRRSIGs :: Positive -> a -> ([RD_RRSIG] -> a) -> a
positiveRRSIGs pos nothing just = positiveHit (const nothing) (\_ sigs -> just sigs) pos

---

-- Ranking data (section 5.4.1 of RFC2181 - Clarifications to the DNS Specification)
-- <https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1>

data Ranking
    = {- + Additional information from an authoritative answer,
           Data from the authority section of a non-authoritative answer,
           Additional information from non-authoritative answers. -}
      RankAdditional
    | {- + Data from the answer section of a non-authoritative answer, and
           non-authoritative data from the answer section of authoritative
           answers, -}
      RankAnswer
    | {- + Glue from a primary zone, or glue from a zone transfer, -}
      --
      {- + Data from the authority section of an authoritative answer, -}
      -- -- avoiding issue of authority section in reply with aa flag
      {- + The authoritative data included in the answer section of an
           authoritative reply. -}
      RankAuthAnswer
    {- + Data from a zone transfer, other than glue, -}
    --
    {- + Data from a primary zone file, other than glue data, -}
    --
    deriving (Eq, Ord, Show)

-- ranking, derived order, the lower the beter

rankedSection
    :: Ranking
    -> Ranking
    -> (DNSMessage -> [ResourceRecord])
    -> DNSMessage
    -> ([ResourceRecord], Ranking)
rankedSection authRank noauthRank section msg =
    (,) (section msg) $
        if DNS.authAnswer flags then authRank else noauthRank
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

data Val = Val CRSet Ranking deriving (Show)

data Cache = Cache (OrdPSQ Question EpochTime Val) Int {- max size -}

empty :: Int -> Cache
empty = Cache PSQ.empty

null :: Cache -> Bool
null (Cache psq _) = PSQ.null psq

lookup
    :: EpochTime
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Maybe ([ResourceRecord], Ranking)
lookup now dom typ cls = lookupAlive now result dom typ cls
  where
    result ttl crs rank = Just (extractRRSet dom typ cls ttl crs, rank)

-- when cache has EMPTY, returns SOA
lookupEither
    :: EpochTime
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Maybe (Either ([ResourceRecord], Ranking) [ResourceRecord], Ranking {- SOA or RRs, ranking -})
lookupEither now dom typ cls cache = lookupAlive now result dom typ cls cache
  where
    result ttl crs rank = case crs of
        Negative soaDom -> do
            sp <- lookupAlive now (soaResult ttl soaDom) soaDom SOA DNS.classIN cache {- EMPTY hit. empty ranking and SOA result. -}
            return (Left sp, rank)
        _ ->
            Just (Right $ extractRRSet dom typ DNS.classIN ttl crs, rank)
    soaResult ettl srcDom ttl crs rank =
        Just (extractRRSet srcDom SOA DNS.classIN (ettl `min` ttl {- treated as TTL of empty data -}) crs, rank)

lookupAlive
    :: EpochTime
    -> (TTL -> CRSet -> Ranking -> Maybe a)
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Maybe a
lookupAlive now mk dom typ cls = lookup_ mkAlive $ Question dom typ cls
  where
    mkAlive eol crset rank = do
        ttl <- alive now eol
        mk ttl crset rank

-- lookup interface for stub resolver
stubLookup :: Question -> Cache -> Maybe (EpochTime, CRSet)
stubLookup k = lookup_ result k
  where
    result eol crs _ = Just (eol, crs)

lookup_
    :: (EpochTime -> CRSet -> Ranking -> Maybe a)
    -> Question
    -> Cache
    -> Maybe a
lookup_ mk k (Cache cache _) = do
    (eol, Val crset rank) <- k `PSQ.lookup` cache
    mk eol crset rank

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -Wno-incomplete-uni-patterns

-- |
-- >>> c0 = empty 256
-- >>> dump <$> insertRRs 0 [] RankAnswer c0
-- Nothing
-- >>> Just c1 = insertRRs 0 [ResourceRecord "example.com." A DNS.classIN 1 (DNS.rd_a "192.168.1.1"), ResourceRecord "a.example.com." A DNS.classIN 1 (DNS.rd_a "192.168.32.1"), ResourceRecord "example.com." A DNS.classIN 1 (DNS.rd_a "192.168.1.2")] RankAnswer c0
-- >>> mapM_ print $ dump c1
-- (Question {qname = "example.com.", qtype = A, qclass = 1},(1,Val (Positive (NotVerified [192.168.1.1,192.168.1.2])) RankAnswer))
-- (Question {qname = "a.example.com.", qtype = A, qclass = 1},(1,Val (Positive (NotVerified [192.168.32.1])) RankAnswer))
insertRRs :: EpochTime -> [ResourceRecord] -> Ranking -> Cache -> Maybe Cache
insertRRs now rrs rank = updateAll
  where
    updateAll = foldr compU (const Nothing) [u | cps <- is, let u = update cps]
    update rrsetCPS c = rrsetCPS $ \key ttl cr srank -> insert now key ttl cr srank c
    (_errs, is) = insertSetFromSection rrs rank

    compU :: (a -> Maybe a) -> (a -> Maybe a) -> (a -> Maybe a)
    compU u au c = maybe (u c) u $ au c

-- |
--   Insert RR-list example with error-handling
--
-- @
--    case insertSetFromSection rrList rank of
--      (errRRLists, rrsets) ->
--        ...
--        [ k (insert now) cache  -- insert Maybe action
--        | k <- rrsets
--        ]
--        ...
--        ... errRRLists ...  -- error handlings
-- @
--
--   Insert empty-RRSet example for negative cache
-- @
--    insertSetEmpty sdom dom typ ttl rank (insert now) cache  -- insert Maybe action
-- @
insert :: EpochTime -> Question -> TTL -> CRSet -> Ranking -> Cache -> Maybe Cache
insert now k@(Question dom typ cls) ttl crs rank cache@(Cache c xsz) =
    maybe sized withOldRank lookupRank
  where
    lookupRank =
        lookupAlive
            now
            (\_ _crset r -> Just r)
            dom
            typ
            cls
            cache
    withOldRank r = do
        guard $ rank > r
        inserted -- replacing rank does not change size
    eol = now <+ ttl
    inserted = Just $ Cache (PSQ.insert k eol (Val crs rank) c) xsz
    sized
        | PSQ.size c < xsz = inserted
        | otherwise = do
            (_, l, _, deleted) <- PSQ.minView c
            guard $ eol > l -- Guard if the tried to insert has the smallest lifetime
            Just $ Cache (PSQ.insert k eol (Val crs rank) deleted) xsz

-- insert interface for stub resolver
stubInsert :: Question -> EpochTime -> CRSet -> Cache -> Maybe Cache
stubInsert k eol crs (Cache c xsz) =
    sized
  where
    rank = RankAnswer
    inserted = Just $ Cache (PSQ.insert k eol (Val crs rank) c) xsz
    sized
        | PSQ.size c < xsz = inserted
        | otherwise = do
            (_, l, _, deleted) <- PSQ.minView c
            guard $ eol > l -- Guard if the tried to insert has the smallest lifetime
            Just $ Cache (PSQ.insert k eol (Val crs rank) deleted) xsz

expires :: EpochTime -> Cache -> Maybe Cache
expires now (Cache c xsz) =
    case PSQ.findMin c of
        Just (_, eol, _)
            | eol <= now -> Just $ Cache (snd $ PSQ.atMostView now c) xsz
            | otherwise -> Nothing
        Nothing -> Nothing

alive :: EpochTime -> EpochTime -> Maybe TTL
alive now eol = do
    let ttl' = eol - now
        safeToTTL :: EpochTime -> Maybe TTL
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

-- | Key for NameError
pattern NX :: TYPE
pattern NX = TYPE 0xff00

---
{- debug interfaces -}

member
    :: EpochTime
    -> Domain
    -> TYPE
    -> CLASS
    -> Cache
    -> Bool
member now dom typ cls = isJust . lookupAlive now (\_ _ _ -> Just ()) dom typ cls

dump :: Cache -> [(Question, (EpochTime, Val))]
dump (Cache c _) = [(k, (eol, v)) | (k, eol, v) <- PSQ.toAscList c]

dumpKeys :: Cache -> [(Question, EpochTime)]
dumpKeys (Cache c _) = [(k, eol) | (k, eol, _v) <- PSQ.toAscList c]

---

(<+) :: EpochTime -> TTL -> EpochTime
now <+ ttl = now + fromIntegral ttl

infixl 6 <+

toRDatas :: CRSet -> ([RData], [RD_RRSIG])
toRDatas = unCRSet (const ([], [])) (\rs -> (rs, [])) (,)

fromRDatas :: [RData] -> Maybe CRSet
fromRDatas rds = rds `listseq` notVerified rds Nothing Just
  where
    listRnf :: [a] -> ()
    listRnf = liftRnf (`seq` ())
    listseq :: [a] -> b -> b
    listseq ps q = case listRnf ps of () -> q

rrSetKey :: ResourceRecord -> Maybe Question
rrSetKey (ResourceRecord rrname rrtype rrclass _rrttl rd)
    | rrclass == DNS.classIN && DNS.rdataType rd == rrtype =
        Just (Question rrname rrtype rrclass)
    | otherwise = Nothing

takeRRSet :: [ResourceRecord] -> Maybe ((Question -> TTL -> CRSet -> a) -> a)
takeRRSet [] = Nothing
takeRRSet rrs@(_ : _) = do
    ps <- mapM rrSetKey rrs -- rrtype and rdata are consistent for each RR
    guard $ length (group ps) == 1 -- query key and TLL are equal for each elements
    (k', _) <- uncons ps -- always success because rrs is not null.
    let ttl = minimum $ map DNS.rrttl rrs -- always exist because rrs is not null.
    rds <- fromRDatas $ map DNS.rdata rrs
    return $ \h -> h k' ttl rds

{- FOURMOLU_DISABLE -}
extractRRSet :: Domain -> TYPE -> CLASS -> TTL -> CRSet -> [ResourceRecord]
extractRRSet dom ty cls ttl crs =
    [ResourceRecord dom ty cls ttl rd | rd <- rds] ++
    [ResourceRecord dom RRSIG cls ttl $ DNS.toRData sig | sig <- ss]
  where
    (rds, ss) = toRDatas crs
{- FOURMOLU_ENABLE -}

insertSetFromSection
    :: [ResourceRecord]
    -> Ranking
    -> ([[ResourceRecord]], [(Question -> TTL -> CRSet -> Ranking -> a) -> a])
insertSetFromSection rs0 r0 = (errRS, iset rrss r0)
  where
    key rr = (DNS.rrname rr, DNS.rrtype rr, DNS.rrclass rr)
    getRRSet rs = maybe (Left rs) Right $ takeRRSet rs
    (errRS, rrss) = partitionEithers . map getRRSet . groupBy ((==) `on` key) . sortOn key $ rs0
    iset ss rank = [\h -> rrset $ \k ttl cr -> h k ttl cr rank | rrset <- ss]

insertSetEmpty
    :: Domain
    -> Domain
    -> TYPE
    -> TTL
    -> Ranking
    -> ((Question -> TTL -> CRSet -> Ranking -> a) -> a)
insertSetEmpty soaDom dom typ ttl rank h = soaDom `seq` h key ttl (Negative soaDom) rank
  where
    key = Question dom typ DNS.classIN
