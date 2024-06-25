{-# LANGUAGE PatternSynonyms #-}

module DNS.RRCache.Types (
    -- * cache interfaces
    empty,
    null,
    lookupAlive,
    insert,
    expires,
    insertWithExpires,
    remove,
    filters,
    size,
    maxSize,
    stubLookup,
    stubInsert,
    Ranking (..),
    RankedSectionCPS,
    getRank,
    getRanked,
    rkAnswer,
    rkAuthority,
    rkAdditional,
    rankedAnswer,
    rankedAuthority,
    rankedAdditional,
    cpsInsertSection,
    cpsInsertNegative,
    cpsInsertNegativeNoSOA,
    TYPE (ERR, NX),

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
    RDatas,
    RRSIGs,
    positiveRDatas,
    positiveRRSIGs,
    --
    Positive (..),
    positiveCases,
    Negative (..),
    negativeCases,
    Hit (..),
    hitCases1,
    hitCases,
    --
    mkNoSig,
    noSig,
    mkCheckDisabled,
    checkDisabled,
    mkValid,
    valid,
    negWithSOA,
    negNoSOA,

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
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ

-- dnsext packages
import DNS.SEC (RD_RRSIG, TYPE (RRSIG))
import DNS.Types (
    CLASS,
    DNSMessage,
    Domain,
    Question (..),
    RCODE,
    RData,
    ResourceRecord (ResourceRecord),
    TTL,
 )
import qualified DNS.Types as DNS
import DNS.Types.Internal (TYPE (..))
import DNS.Types.Time (EpochTime)

---

cons1 :: [a] -> b -> (a -> [a] -> b) -> b
cons1 [] nil _ = nil
cons1 (x : xs) _ cons = cons x xs

type RDatas = NonEmpty RData
type RRSIGs = NonEmpty RD_RRSIG

{- FOURMOLU_DISABLE -}
data Positive
    = PosNoSig RDatas              {- request RRSIG, but not returned -}
    | PosCheckDisabled RDatas      {- only for check-disabled state. may verify again  -}
    {-- | PosVerifyFailed RDatas   {- verification failed -} {- unused state -} --}
    | PosValid RDatas RRSIGs       {- verification succeeded -}
    deriving (Eq, Show)

positiveCases :: ([RData] -> a) -> ([RData] -> a) -> ([RData] -> [RD_RRSIG] -> a) -> Positive -> a
positiveCases notVerified_ checkDisabled_ valid_ pos = case pos of
    PosNoSig rds          -> notVerified_ $ NE.toList rds
    PosCheckDisabled rds  -> checkDisabled_ $ NE.toList rds
    PosValid rds ss       -> valid_ (NE.toList rds) (NE.toList ss)

data Negative
    = NegSOA Domain                {- NXDOMAIN or NODATA with SOA, hold zone-domain delegation from -}
    | NegNoSOA RCODE               {- without SOA -}
    deriving (Eq, Show)

negativeCases :: (Domain -> a) -> (RCODE -> a) -> Negative -> a
negativeCases withSOA_ withoutSOA_ neg = case neg of
    NegSOA zone  -> withSOA_ zone
    NegNoSOA rc  -> withoutSOA_ rc

-- cache hit cases
data Hit
    = Negative Negative            {- Negative hit -}
    | Positive Positive            {- Positive hit -}
    deriving (Eq, Show)

hitCases1 :: (Negative -> a) -> (Positive -> a) -> Hit -> a
hitCases1 negative_ posivtive_ hit = case hit of
    Negative neg  -> negative_ neg
    Positive pos  -> posivtive_ pos

hitCases :: (Domain -> a) -> (RCODE -> a) -> ([RData] -> a) -> ([RData] -> a) -> ([RData] -> [RD_RRSIG] -> a) -> Hit -> a
hitCases soa_ nsoa_ notVerified_ checkDisabled_ valid_ =
    hitCases1 (negativeCases soa_ nsoa_) (positiveCases notVerified_ checkDisabled_ valid_)
{- FOURMOLU_ENABLE -}

mkNoSig :: RData -> [RData] -> Hit
mkNoSig d ds = Positive $ PosNoSig (d :| ds)

noSig :: [RData] -> a -> (Hit -> a) -> a
noSig rds nothing just = cons1 rds nothing ((just .) . mkNoSig)

mkCheckDisabled :: RData -> [RData] -> Hit
mkCheckDisabled d ds = Positive $ PosCheckDisabled (d :| ds)

checkDisabled :: [RData] -> a -> (Hit -> a) -> a
checkDisabled rds nothing just = cons1 rds nothing ((just .) . mkCheckDisabled)

mkValid :: RData -> [RData] -> RD_RRSIG -> [RD_RRSIG] -> Hit
mkValid d ds s ss = Positive $ PosValid (d :| ds) (s :| ss)

valid :: [RData] -> [RD_RRSIG] -> a -> (Hit -> a) -> a
valid rds sigs nothing just = cons1 rds nothing withRds
  where
    withRds d ds = cons1 sigs nothing withSigs
      where
        withSigs s ss = just $ mkValid d ds s ss

negWithSOA :: Domain -> Hit
negWithSOA = Negative . NegSOA

negNoSOA :: RCODE -> Hit
negNoSOA = Negative . NegNoSOA

positiveRDatas :: Positive -> [RData]
positiveRDatas = positiveCases id id const

positiveRRSIGs :: Positive -> a -> ([RD_RRSIG] -> a) -> a
positiveRRSIGs pos nothing just = positiveCases (const nothing) (const nothing) (\_ sigs -> just sigs) pos

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

type RankedSectionK a = Ranking -> Ranking -> (DNSMessage -> [ResourceRecord]) -> a
type RankedSectionCPS a = RankedSectionK a -> a

mkRankedSection
    :: Ranking
    -> Ranking
    -> (DNSMessage -> [ResourceRecord])
    -> RankedSectionCPS a
mkRankedSection authRank noauthRank section k = k authRank noauthRank section

getRankK :: RankedSectionK (DNSMessage -> Ranking)
getRankK authRank noauthRank _ msg = if DNS.authAnswer (DNS.flags msg) then authRank else noauthRank

getRankedSectionK :: RankedSectionK (DNSMessage -> ([ResourceRecord], Ranking))
getRankedSectionK authRank noauthRank section msg = (section msg, getRankK authRank noauthRank section msg)

getRank :: RankedSectionCPS (DNSMessage -> Ranking)
           -> DNSMessage -> Ranking
getRank cps = cps getRankK

getRanked :: RankedSectionCPS (DNSMessage -> ([ResourceRecord], Ranking))
          -> DNSMessage -> ([ResourceRecord], Ranking)
getRanked cps = cps getRankedSectionK

rkAnswer :: RankedSectionCPS a
rkAnswer = mkRankedSection RankAuthAnswer RankAnswer DNS.answer

{- FOURMOLU_DISABLE -}
rkAuthority :: RankedSectionCPS a
rkAuthority = mkRankedSection RankAdditional RankAdditional DNS.authority
             {- avoid security hole with authorized reply and authority section case.
                RankAdditional does not overwrite glue. -}
{- FOURMOLU_ENABLE -}

rkAdditional :: RankedSectionCPS a
rkAdditional = mkRankedSection RankAdditional RankAdditional DNS.additional

rankedAnswer :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAnswer = getRanked rkAnswer

rankedAuthority :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAuthority = getRanked rkAuthority

rankedAdditional :: DNSMessage -> ([ResourceRecord], Ranking)
rankedAdditional = getRanked rkAdditional

---

data Val = Val Hit Ranking deriving (Show)

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

{- FOURMOLU_DISABLE -}
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
        Negative neg  -> negativeCases (wsoa_ ttl rank) (nsoa_ rank) neg
        Positive {}   -> Just (Right $ extractRRSet dom typ DNS.IN ttl crs, rank)
    wsoa_ ttl rank soaDom = do
        sp <- lookupAlive now (soaResult ttl soaDom) soaDom SOA DNS.IN cache {- EMPTY hit. empty ranking and SOA result. -}
        Just (Left sp, rank)
    nsoa_ rank _rc = Just (Left ([], RankAdditional {- FIXME, dummy rank value for no-SOA -}), rank)
    soaResult ettl srcDom ttl crs rank =
        Just (extractRRSet srcDom SOA DNS.IN (ettl `min` ttl {- treated as TTL of empty data -}) crs, rank)
{- FOURMOLU_ENABLE -}

lookupAlive
    :: EpochTime
    -> (TTL -> Hit -> Ranking -> Maybe a)
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
stubLookup :: Question -> Cache -> Maybe (EpochTime, Hit)
stubLookup k = lookup_ result k
  where
    result eol crs _ = Just (eol, crs)

lookup_
    :: (EpochTime -> Hit -> Ranking -> Maybe a)
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
-- >>> Just c1 = insertRRs 0 [ResourceRecord "example.com." A DNS.IN 1 (DNS.rd_a "192.168.1.1"), ResourceRecord "a.example.com." A DNS.IN 1 (DNS.rd_a "192.168.32.1"), ResourceRecord "example.com." A DNS.IN 1 (DNS.rd_a "192.168.1.2")] RankAnswer c0
-- >>> mapM_ print $ dump c1
-- (Question {qname = "example.com.", qtype = A, qclass = IN},(1,Val (Positive (PosNoSig (192.168.1.1 :| [192.168.1.2]))) RankAnswer))
-- (Question {qname = "a.example.com.", qtype = A, qclass = IN},(1,Val (Positive (PosNoSig (192.168.32.1 :| []))) RankAnswer))
insertRRs :: EpochTime -> [ResourceRecord] -> Ranking -> Cache -> Maybe Cache
insertRRs now rrs rank = updateAll
  where
    updateAll = foldr compU (const Nothing) [u | cps <- is, let u = update cps]
    update rrsetCPS c = rrsetCPS $ \key ttl cr srank -> insert now key ttl cr srank c
    (_errs, is) = cpsInsertSection rrs rank

    compU :: (a -> Maybe a) -> (a -> Maybe a) -> (a -> Maybe a)
    compU u au c = maybe (u c) u $ au c

-- |
--   Insert RR-list example with error-handling
--
-- @
--    case cpsInsertSection rrList rank of
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
--    cpsInsertNegative sdom dom typ ttl rank (insert now) cache  -- insert Maybe action
-- @
insert :: EpochTime -> Question -> TTL -> Hit -> Ranking -> Cache -> Maybe Cache
insert _ _ _ _ _ (Cache _ xsz) | xsz <= 0 = Nothing
insert now k@(Question dom typ cls) ttl crs rank cache@(Cache c xsz) =
    maybe sized withOldPRI lookupRank
  where
    lookupRank =
        lookupAlive
            now
            (\_ ohit r -> Just (verifiedPRI ohit, r))
            dom
            typ
            cls
            cache
    withOldPRI (vp, r) = do
        let nvp = verifiedPRI crs
        guard $ (nvp > vp) || (nvp == vp) && rank > r
        inserted -- replacing rank does not change size
    sized
        | PSQ.size c < xsz = inserted
        | otherwise = do
            (_, l, _, deleted) <- PSQ.minView c
            guard $ eol > l -- Guard if the tried to insert has the smallest lifetime
            Just $ Cache (PSQ.insert k eol (Val crs rank) deleted) xsz
    --
    verifiedPRI = hitCases1 (\_ -> VP_NoCD) (positiveCases (\_ -> VP_NoCD) (\_ -> VP_CD) (\_ _ -> VP_NoCD))
    inserted = Just $ Cache (PSQ.insert k eol (Val crs rank) c) xsz
    eol = now <+ ttl

data VerifiedPriority
    = VP_CD
    | VP_NoCD
    deriving (Eq, Ord)

-- insert interface for stub resolver
stubInsert :: Question -> EpochTime -> Hit -> Cache -> Maybe Cache
stubInsert _ _ _ (Cache _ xsz) | xsz <= 0 = Nothing
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

insertWithExpires :: EpochTime -> Question -> TTL -> Hit -> Ranking -> Cache -> Maybe Cache
insertWithExpires now k ttl crs rank = withExpire
  where
    ins = insert now k ttl crs rank
    withExpire cache = maybe (ins cache) ins $ expires now cache {- expires before insert -}

remove :: Question -> Cache -> Cache
remove k (Cache psq xsz) = Cache (PSQ.delete k psq) xsz

filters :: (Question -> EpochTime -> Hit -> Ranking -> Bool) -> Cache -> Cache
filters p (Cache c xsz) =
    let c' = PSQ.fromList [t | t@(k, eol, Val hit rank) <- PSQ.toAscList c, p k eol hit rank]
    in  Cache c' xsz

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

maxSize :: Cache -> Int
maxSize (Cache _ xsz) = xsz

-- | Key for error RCODE
--   * Negative       - NameErr
--   * NegativeNoSOA  - NameErr or other errors RCODE
--
-- code from Reserved for Private Use (section 3.1 of RFC6895)
-- <https://datatracker.ietf.org/doc/html/rfc6895#section-3.1>
pattern ERR :: TYPE
pattern ERR = TYPE 0xff00

{-# DEPRECATED NX "use ERR instead of this" #-}
-- | same as `ERR`, backword compat
pattern NX :: TYPE
pattern NX = ERR

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

toRDatas :: Hit -> ([RData], [RD_RRSIG])
toRDatas = hitCases (const ([], [])) (const ([], [])) (\rs -> (rs, [])) (\rs -> (rs, [])) (,)

fromRDatas :: [RData] -> Maybe Hit
fromRDatas rds = rds `listseq` noSig rds Nothing Just
  where
    listRnf :: [a] -> ()
    listRnf = liftRnf (`seq` ())
    listseq :: [a] -> b -> b
    listseq ps q = case listRnf ps of () -> q

rrSetKey :: ResourceRecord -> Maybe Question
rrSetKey (ResourceRecord rrname rrtype rrclass _rrttl rd)
    | rrclass == DNS.IN && DNS.rdataType rd == rrtype =
        Just (Question rrname rrtype rrclass)
    | otherwise = Nothing

takeRRSet :: [ResourceRecord] -> Maybe ((Question -> TTL -> Hit -> a) -> a)
takeRRSet [] = Nothing
takeRRSet rrs@(_ : _) = do
    ps <- mapM rrSetKey rrs -- rrtype and rdata are consistent for each RR
    guard $ length (group ps) == 1 -- query key and TLL are equal for each elements
    (k', _) <- uncons ps -- always success because rrs is not null.
    let ttl = minimum $ map DNS.rrttl rrs -- always exist because rrs is not null.
    rds <- fromRDatas $ map DNS.rdata rrs
    return $ \h -> h k' ttl rds

{- FOURMOLU_DISABLE -}
extractRRSet :: Domain -> TYPE -> CLASS -> TTL -> Hit -> [ResourceRecord]
extractRRSet dom ty cls ttl crs =
    [ResourceRecord dom ty cls ttl rd | rd <- rds] ++
    [ResourceRecord dom RRSIG cls ttl $ DNS.toRData sig | sig <- ss]
  where
    (rds, ss) = toRDatas crs
{- FOURMOLU_ENABLE -}

cpsInsertSection
    :: [ResourceRecord]
    -> Ranking
    -> ([[ResourceRecord]], [(Question -> TTL -> Hit -> Ranking -> a) -> a])
cpsInsertSection rs0 r0 = (errRS, iset rrss r0)
  where
    key rr = (DNS.rrname rr, DNS.rrtype rr, DNS.rrclass rr)
    getRRSet rs = maybe (Left rs) Right $ takeRRSet rs
    (errRS, rrss) = partitionEithers . map getRRSet . groupBy ((==) `on` key) . sortOn key $ rs0
    iset ss rank = [\h -> rrset $ \k ttl cr -> h k ttl cr rank | rrset <- ss]

{- FOURMOLU_DISABLE -}
cpsInsertNegative
    :: Domain
    -> Domain -> TYPE -> TTL -> Ranking
    -> ((Question -> TTL -> Hit -> Ranking -> a) -> a)
cpsInsertNegative soaDom dom typ ttl rank h = soaDom `seq` h key ttl (negWithSOA soaDom) rank
  where
    key = Question dom typ DNS.IN

cpsInsertNegativeNoSOA
    :: RCODE
    -> Domain -> TYPE -> TTL -> Ranking
    -> ((Question -> TTL -> Hit -> Ranking -> a) -> a)
cpsInsertNegativeNoSOA rcode dom typ ttl rank h = rcode `seq` h key ttl (negNoSOA rcode) rank
  where
    key = Question dom typ DNS.IN
{- FOURMOLU_ENABLE -}
