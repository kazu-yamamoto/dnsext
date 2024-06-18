{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module CacheProp (
    props,
    run,
)
where

-- GHC packages
import Control.Monad (unless)
import Data.Char (toLower, toUpper)
import Data.List (sort)
import Data.Maybe (mapMaybe)
import Data.String (IsString)
import Data.UnixTime (UnixTime (..), getUnixTime)
import Foreign.C.Types (CTime (..))
import System.Exit (exitFailure)
import System.IO.Unsafe (unsafePerformIO)

-- others
import Test.QuickCheck

-- dnsext packages
import DNS.Types (Domain, Seconds (..), TTL, TYPE (..))
import qualified DNS.Types as DNS
import DNS.Types.Time (EpochTime)

-- this package
import DNS.RRCache (
    Cache,
    Question (..),
    Ranking (..),
    Val (Val),
    extractRRSet,
    takeRRSet,
    (<+),
 )
import qualified DNS.RRCache as Cache

-----

domainList :: [String]
domainList =
    [ "example.com."
    , "example.org."
    , "example.ne.jp."
    , "example.net.uk."
    , "example.com.cn."
    ]

nameList :: [String]
nameList =
    [ "www.example.com."
    , "mail.example.com."
    , "example.ne.jp."
    , "www.example.or.jp."
    , "mail.example.ne.jp."
    ]

sbsDomainList :: [Domain]
sbsDomainList = map DNS.fromRepresentation domainList

v4List :: IsString a => [a]
v4List = ["192.168.10.1", "192.168.10.2", "192.168.10.3", "192.168.10.4"]

v6List :: IsString a => [a]
v6List =
    ["fe80::000a:0001", "fe80::000a:0002", "fe80::000a:0003", "fe80::000a:0004"]

nsList :: [Domain]
nsList =
    [ "ns1.example.com."
    , "ns2.example.com."
    , "ns3.example.com."
    , "ns4.example.com."
    , "ns5.example.com."
    ]

ts0 :: EpochTime
ts0 = unsafePerformIO $ do
    UnixTime (CTime tim) _ <- getUnixTime
    return tim
{-# NOINLINE ts0 #-}

-- avoid limitations imposed by max-size
cacheEmpty :: Cache
cacheEmpty = Cache.empty 4096

-----

data Update
    = I Question TTL Val
    | E
    deriving (Show)

runUpdate :: EpochTime -> Update -> Cache -> Cache
runUpdate t u = case u of
    I k ttl (Val crs rank) -> may $ Cache.insert t k ttl crs rank
    E -> may $ Cache.expires t
  where
    may f c = maybe c id $ f c

foldUpdates :: [(EpochTime, Update)] -> Cache -> Cache
foldUpdates = foldr (\p k -> k . uncurry runUpdate p) id

removeKeyUpdates :: Question -> [(EpochTime, Update)] -> [(EpochTime, Update)]
removeKeyUpdates k = filter (not . match)
  where
    match (_, I ik _ _) = k == ik
    match (_, E) = False

removeExpiresUpdates :: [(EpochTime, Update)] -> [(EpochTime, Update)]
removeExpiresUpdates = filter (not . expire)
  where
    expire (_, E) = True
    expire _ = False

rankings :: [Ranking]
rankings = [RankAuthAnswer, RankAnswer, RankAdditional]

-----

genCrsAssoc :: [(TYPE, Gen Cache.Hit)]
genCrsAssoc =
    [ (A, crset . (DNS.rd_a <$>) <$> listOf1 (elements v4List))
    , (NS, crset . (DNS.rd_ns <$>) <$> listOf1 (elements nsList))
    , (AAAA, crset . (DNS.rd_aaaa <$>) <$> listOf1 (elements v6List))
    ]
  where
    crset [] = error "genCrsAssoc: only not empty allowed"
    crset (d : ds) = Cache.mkNoSig d ds

toULString :: String -> Gen String
toULString s = zipWith ulc <$> vectorOf (length s) arbitrary <*> pure s
  where
    ulc upper
        | upper = toUpper
        | otherwise = toLower

genWrongCRPair :: Gen (Question, Cache.Hit)
genWrongCRPair = do
    (typ, genCrs) <- elements wrongs
    key <- Question <$> elements sbsDomainList <*> pure typ <*> pure DNS.IN
    crs <- genCrs
    pure (key, crs)
  where
    wrongs =
        [ (typ, genCrs)
        | typ <- [A, NS, AAAA]
        , (gtyp, genCrs) <- genCrsAssoc
        , typ /= gtyp
        ]

genCRsRec :: Gen ((Question, Gen Cache.Hit), Domain)
genCRsRec = do
    (typ, genCrs) <- elements genCrsAssoc
    let labelList
            | typ `elem` [NS, SOA, MX] = domainList
            | otherwise = nameList
    lbl <- elements labelList
    (,) (Question (DNS.fromRepresentation lbl) typ DNS.IN, genCrs)
        <$> (DNS.fromRepresentation <$> toULString lbl)

genCRsPair :: Gen (Question, Gen Cache.Hit)
genCRsPair = fst <$> genCRsRec

genCRPair :: Gen (Question, Cache.Hit)
genCRPair = do
    (key, genCrs) <- genCRsPair
    crs <- genCrs
    pure (key, crs)

genTTL :: Gen TTL
genTTL = Seconds <$> choose (1, 7200000)

genRanking :: Gen Ranking
genRanking = elements rankings

genEpochTime :: Gen EpochTime
genEpochTime = (ts0 <+) . Seconds <$> choose (1, 21600000)

genUpdate :: Gen Update
genUpdate =
    frequency
        [ (32, genInsert)
        , (1, pure E)
        ]
  where
    genInsert = do
        (k, crs) <- genCRPair
        I k <$> genTTL <*> (Val crs <$> genRanking)

genUpdates :: Gen [(EpochTime, Update)]
genUpdates = do
    ks <- listOf genUpdate
    tss <- sort <$> vectorOf (length ks) genEpochTime
    pure $ zip tss ks

genRankOrds :: Gen (Ranking, Ranking)
genRankOrds = elements ords
  where
    ords = [(r1, r2) | r1 <- rankings, r2 <- rankings, r1 > r2]

-- ordered pairs

genRankOrdsCo :: Gen (Ranking, Ranking)
genRankOrdsCo = elements ordsCo
  where
    ordsCo = [(r1, r2) | r1 <- rankings, r2 <- rankings, r1 <= r2]

-- complement pairs

-----

newtype AKey = AKey Question deriving (Show)

instance Arbitrary AKey where
    arbitrary =
        AKey
            <$> ( Question
                    <$> elements sbsDomainList
                    <*> elements [A, NS, AAAA]
                    <*> pure DNS.IN
                )

newtype AWrongCRPair = AWrongCRPair (Question, Cache.Hit) deriving (Show)

instance Arbitrary AWrongCRPair where
    arbitrary = AWrongCRPair <$> genWrongCRPair

newtype ATTL = ATTL TTL deriving (Show)

instance Arbitrary ATTL where
    arbitrary = ATTL <$> genTTL

newtype ACRPair = ACRPair (Question, Cache.Hit) deriving (Show)

instance Arbitrary ACRPair where
    arbitrary = ACRPair <$> genCRPair

newtype ACRRec = ACRRec (Question, Cache.Hit, Domain) deriving (Show)

instance Arbitrary ACRRec where
    arbitrary =
        ACRRec <$> do
            ((key, genCrs), uldom) <- genCRsRec
            crs <- genCrs
            pure (key, crs, uldom)

newtype ARanking = ARanking Ranking deriving (Show)

instance Arbitrary ARanking where
    arbitrary = ARanking <$> genRanking

newtype AEpochTime = AEpochTime EpochTime deriving (Show)

instance Arbitrary AEpochTime where
    arbitrary = AEpochTime <$> genEpochTime

newtype AUpdates = AUpdates [(EpochTime, Update)] deriving (Show)

instance Arbitrary AUpdates where
    arbitrary = AUpdates <$> genUpdates

newtype ARankOrds = ARankOrds (Ranking, Ranking) deriving (Show)

instance Arbitrary ARankOrds where
    arbitrary = ARankOrds <$> genRankOrds

newtype ARankOrdsCo = ARankOrdsCo (Ranking, Ranking) deriving (Show)

instance Arbitrary ARankOrdsCo where
    arbitrary = ARankOrdsCo <$> genRankOrdsCo

newtype ACR2 = ACR2 (Question, (Cache.Hit, Cache.Hit)) deriving (Show)

instance Arbitrary ACR2 where
    arbitrary = ACR2 <$> gen
      where
        gen = do
            (k, genCrs) <- genCRsPair
            (,) k <$> ((,) <$> genCrs <*> genCrs)

-----

-- RRSet refine

-- forall ((k, crs) :: AWrongCRPair) ttl . takeRRSet (extractRRSet k ttl crs) == Nothing
rrsetTakeNothing :: AWrongCRPair -> ATTL -> Property
rrsetTakeNothing (AWrongCRPair (Question dom typ cls, crs)) (ATTL ttl) = fmap ($ (,,)) (takeRRSet $ extractRRSet dom typ cls ttl crs) === Nothing

-- forall ((k, crs) :: ACRPair) ttl . takeRRSet (extractRRSet k ttl crs) == Just ((k, ttl), crs)
rrsetExtractTake :: ACRPair -> ATTL -> Property
rrsetExtractTake (ACRPair (k@(Question dom typ cls), crs)) (ATTL ttl) =
    fmap ($ (,,)) (takeRRSet $ extractRRSet dom typ cls ttl crs)
        === Just (k, ttl, crs)

---

-- cache size

-- Cache.size Cache.empty == 0
sizeEmpty :: Property
sizeEmpty = once $ Cache.size cacheEmpty === 0

sizeSatisfyMax :: AUpdates -> Property
sizeSatisfyMax (AUpdates us) =
    label "leeway" (Cache.size cache < maxCacheSize)
        .||. label "max" (Cache.size cache === maxCacheSize)
  where
    maxCacheSize = 10
    cache = foldUpdates us $ Cache.empty maxCacheSize

-- size of cache after new key is inserted
sizeNewInserted :: ACRPair -> ATTL -> ARanking -> AUpdates -> Property
sizeNewInserted (ACRPair (k, crs)) (ATTL ttl_) (ARanking rank) (AUpdates us) =
    maybe (property False) checkSize $
        Cache.insert ts0 k ttl_ crs rank rcache
  where
    checkSize ins = Cache.size ins === Cache.size rcache + 1
    rcache = foldUpdates (removeKeyUpdates k us) cacheEmpty -- removing Key to be inserted

-- forall ((k, crs) :: ACRPair) ttl cache rs . (rs == extractRRSet k ttl crs) ->
-- (       member k cache  -> size inserted == size cache   \/
--    not (member k cache) -> size inserted == size cache + 1 )
sizeInserted :: ACRPair -> ATTL -> ARanking -> AUpdates -> Property
sizeInserted (ACRPair (k@(Question dom typ cls), crs)) (ATTL ttl_) (ARanking rank) (AUpdates us) =
    maybe (property Discard) checkSize $
        Cache.insert ts0 k ttl_ crs rank cache
  where
    checkSize ins
        | Cache.member ts0 dom typ cls cache =
            label "member" $ Cache.size ins === Cache.size cache
        | otherwise =
            label "normal" $ Cache.size ins === Cache.size cache + 1
    cache = foldUpdates us cacheEmpty

---

-- lookup

lookupEmpty :: AKey -> Property
lookupEmpty (AKey (Question dom typ cls)) = Cache.lookup ts0 dom typ cls cacheEmpty === Nothing

-- lookup key cache after inserted as new key
lookupNewInserted :: ACRRec -> ATTL -> ARanking -> AUpdates -> Property
lookupNewInserted (ACRRec (k@(Question _dom typ cls), crs, ulDom)) (ATTL ttl_) (ARanking rank) (AUpdates us) =
    (Cache.lookup ts0 ulDom typ cls =<< Cache.insert ts0 k ttl_ crs rank rcache)
        =/= Nothing
  where
    rcache = foldUpdates (removeKeyUpdates k us) cacheEmpty -- removing Key to be inserted

lookupInserted :: ACRPair -> ATTL -> ARanking -> AUpdates -> Property
lookupInserted (ACRPair (k@(Question dom typ cls), crs)) (ATTL ttl_) (ARanking rank) (AUpdates us) =
    case Cache.insert ts0 k ttl_ crs rank cache of
        Nothing -> label "old" $ Cache.lookup ts0 dom typ cls cache =/= Nothing
        Just ins -> label "new" $ Cache.lookup ts0 dom typ cls ins =/= Nothing
  where
    cache = foldUpdates us cacheEmpty

lookupTTL :: ACRPair -> ATTL -> ARanking -> AEpochTime -> AUpdates -> Property
lookupTTL (ACRPair (k@(Question dom typ cls), crs)) (ATTL ttl_) (ARanking rank) (AEpochTime ts1) (AUpdates us) =
    maybe (property Discard) checkTTL $
        Cache.insert ts0 k ttl_ crs rank rcache
  where
    rcache = foldUpdates (removeKeyUpdates k us) cacheEmpty -- removing Key to be inserted
    checkTTL ins =
        case map DNS.rrttl . fst <$> Cache.lookup ts1 dom typ cls ins of
            Nothing -> life === Nothing
            Just ttls -> Just ttls === (replicate (length ttls) <$> life)
      where
        life = Cache.alive ts1 (ts0 <+ ttl_)

lookupEither :: AKey -> AUpdates -> Property
lookupEither (AKey (Question dom typ cls)) (AUpdates us) =
    (foldE =<< Cache.lookupEither ts0 dom typ cls cache)
        === Cache.lookup ts0 dom typ cls cache
  where
    cache = foldUpdates us cacheEmpty
    foldE (e, rank) = do
        x <- either (const Nothing) Just e
        return (x, rank)

---

-- ranking

rankingOrdered :: ACR2 -> ATTL -> ATTL -> ARankOrds -> AUpdates -> Property
rankingOrdered (ACR2 (k@(Question dom typ cls), (crs1, crs2))) (ATTL ttl1) (ATTL ttl2) (ARankOrds (r1, r2)) (AUpdates us) =
    maybe (property False) id action
  where
    rcache = foldUpdates (removeKeyUpdates k us) cacheEmpty -- removing Key to be inserted
    action = do
        c2 <- Cache.insert ts0 k ttl2 crs2 r2 rcache
        c1 <- Cache.insert ts0 k ttl1 crs1 r1 c2
        (rrs, rank) <- Cache.lookup ts0 dom typ cls c1
        return $ rrs === extractRRSet dom typ cls ttl1 crs1 .&&. rank === r1

rankingNotOrdered
    :: ACR2 -> ATTL -> ATTL -> ARankOrdsCo -> AUpdates -> Property
rankingNotOrdered (ACR2 (k, (crs1, crs2))) (ATTL ttl1) (ATTL ttl2) (ARankOrdsCo (r1, r2)) (AUpdates us) =
    action === Nothing
  where
    rcache = foldUpdates (removeKeyUpdates k us) cacheEmpty -- removing Key to be inserted
    action = do
        c2 <- Cache.insert ts0 k ttl2 crs2 r2 rcache
        _ <- Cache.insert ts0 k ttl1 crs1 r1 c2
        pure ()

---

-- expires

expiresAlives :: AUpdates -> AEpochTime -> Property
expiresAlives (AUpdates us) (AEpochTime ts1) =
    maybe (property Discard) checkSize $
        Cache.expires ts1 cache
  where
    checkSize ex =
        Cache.size ex
            === length
                [k | (k, ts) <- Cache.dumpKeys cache, Just _ <- [Cache.alive ts1 ts]]
    cache = foldUpdates (removeExpiresUpdates us) cacheEmpty

expiresMaxEOL :: AUpdates -> Property
expiresMaxEOL (AUpdates us) =
    maybe (property Discard) (=== 0) $ do
        mx <- maxEOL
        c <- Cache.expires mx cache
        return $ Cache.size c
  where
    cache = foldUpdates us cacheEmpty
    eol :: (EpochTime, Update) -> Maybe EpochTime
    eol (ts, I _ ttl _) = Just $ ts <+ ttl
    eol (_, E) = Nothing
    maxEOL = case mapMaybe eol us of
        [] -> Nothing
        es@(_ : _) -> Just $ maximum es

-----

props :: [Property]
props =
    [ nprop "RRSet - take nothing" rrsetTakeNothing
    , nprop "RRSet - extract . take is just" rrsetExtractTake
    , nprop "size - empty" sizeEmpty
    , nprop "size - satisfy max" sizeSatisfyMax
    , nprop "size - new inserted" sizeNewInserted
    , nprop "size - inserted" sizeInserted
    , nprop "lookup - empty" lookupEmpty
    , nprop "lookup - new inserted" lookupNewInserted
    , nprop "lookup - inserted" lookupInserted
    , nprop "lookup - ttl" lookupTTL
    , nprop "lookup - lookupEither" lookupEither
    , nprop "ranking - ordered" rankingOrdered
    , nprop "ranking - not ordered" rankingNotOrdered
    , nprop "expires - alives" expiresAlives
    , nprop "expires - with max EOL" expiresMaxEOL
    ]
  where
    nprop name = counterexample ("prop: " ++ name) . label name

runProps :: [Property] -> IO ()
runProps ps = do
    rs <- mapM quickCheckResult ps
    unless (all isSuccess rs) exitFailure

run :: IO ()
run = runProps props

-----
