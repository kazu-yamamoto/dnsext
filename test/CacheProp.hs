{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE FlexibleInstances #-}

module CacheProp
  ( props
  , run
  ) where

import Test.QuickCheck

import Control.Monad (unless)
import Data.Maybe (mapMaybe)
import Data.List (sort)
import Data.Char (ord)
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Network.DNS (TYPE (..), TTL)
import qualified Network.DNS as DNS
import System.IO.Unsafe (unsafePerformIO)
import System.Exit (exitFailure)

import DNSC.Types (Timestamp)
import qualified DNSC.TimeCache as TimeCache
import DNSC.Cache
  (Cache, Key (Key), Val (Val), CRSet (..), (<+),
   Ranking, rankAuthAnswer, rankAnswer, rankAdditional,
   takeRRSet, extractRRSet)
import qualified DNSC.Cache as Cache


{-# ANN module "HLint: ignore Use fromMaybe" #-}

-----

packS8 :: String -> ShortByteString
packS8 = Short.pack . map (fromIntegral . ord)

toDomain :: ShortByteString -> DNS.Domain
toDomain = Short.fromShort

_crsTYPE :: CRSet -> DNS.TYPE
_crsTYPE cr = case cr of
  CR_A     {}  ->  DNS.A
  CR_NS    {}  ->  DNS.NS
  CR_CNAME {}  ->  DNS.CNAME
  CR_SOA   {}  ->  DNS.SOA
  CR_PTR   {}  ->  DNS.PTR
  CR_MX    {}  ->  DNS.MX
  CR_TXT   {}  ->  DNS.TXT
  CR_AAAA  {}  ->  DNS.AAAA

-----

domainList :: [ShortByteString]
domainList =
  map packS8
  [ "example.com."
  , "example.ne.jp."
  , "example.net.uk."
  ]

nameList :: [ShortByteString]
nameList =
  map packS8
  [ "www.example.com."
  , "mail.example.com."
  , "example.ne.jp."
  ]

v4List :: Read a => [a]
v4List = map read [ "192.168.10.1", "192.168.10.2", "192.168.10.3", "192.168.10.4" ]

v6List :: Read a => [a]
v6List = map read [ "fe80::000a:0001", "fe80::000a:0002", "fe80::000a:0003", "fe80::000a:0004" ]

nsList :: [ShortByteString]
nsList =
  map packS8
  [ "ns1.example.com.", "ns2.example.com.", "ns3.example.com."
  , "ns4.example.com.", "ns5.example.com." ]


ts0 :: Timestamp
ts0 = unsafePerformIO $ fst TimeCache.none
{-# NOINLINE ts0 #-}

-----

data Update
  = I Key TTL Val
  | E
  deriving Show

runUpdate :: Timestamp -> Update -> Cache -> Cache
runUpdate t u = case u of
  I k ttl (Val crs rank) -> may $ Cache.insert t k ttl crs rank
  E                      -> may $ Cache.expires t
  where may f c = maybe c id $ f c

foldUpdates :: [(Timestamp, Update)] -> Cache -> Cache
foldUpdates = foldr (\p k -> k . uncurry runUpdate p) id

removeKeyUpdates :: Key -> [(Timestamp, Update)] -> [(Timestamp, Update)]
removeKeyUpdates k = filter (not . match)
  where
    match (_, I ik _ _)  =  k == ik
    match (_, E)         =  False

removeExpiresUpdates :: [(Timestamp, Update)] -> [(Timestamp, Update)]
removeExpiresUpdates = filter (not . expire)
  where
    expire (_, E)  =  True
    expire _       =  False

rankings :: [Ranking]
rankings = [rankAuthAnswer, rankAnswer, rankAdditional]

-----

genCrsAssoc :: [(TYPE, Gen CRSet)]
genCrsAssoc =
  [ (A, CR_A <$> listOf1 (elements v4List))
  , (NS, CR_NS <$> listOf1 (elements nsList))
  , (AAAA, CR_AAAA <$> listOf1 (elements v6List))
  ]

genWrongCRPair :: Gen (Key, CRSet)
genWrongCRPair = do
  (typ, genCrs) <- elements wrongs
  key <- Key <$> elements domainList <*> pure typ <*> pure DNS.classIN
  crs <- genCrs
  pure (key, crs)
  where
    wrongs =
      [ (typ, genCrs)
      | typ <- [A, NS, AAAA]
      , (gtyp, genCrs) <- genCrsAssoc
      , typ /= gtyp
      ]

genCRsPair :: Gen (Key, Gen CRSet)
genCRsPair = do
  (typ, genCrs) <- elements genCrsAssoc
  let labelList
        | typ `elem` [NS, SOA, MX]  =  domainList
        | otherwise                 =  nameList
  (,)
    <$> (Key <$> elements labelList <*> pure typ <*> pure DNS.classIN)
    <*> pure genCrs

genCRPair :: Gen (Key, CRSet)
genCRPair = do
  (key, genCrs) <- genCRsPair
  crs <- genCrs
  pure (key, crs)

genTTL :: Gen TTL
genTTL = choose (1, 7200000)

genRanking :: Gen Ranking
genRanking = elements rankings

genTimestamp :: Gen Timestamp
genTimestamp = (ts0 <+) <$> choose (1, 21600000)

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

genUpdates :: Gen [(Timestamp, Update)]
genUpdates = do
  ks <- listOf genUpdate
  tss <- sort <$> vectorOf (length ks) genTimestamp
  pure $ zip tss ks

genRankOrds :: Gen (Ranking, Ranking)
genRankOrds = elements ords
  where
    ords =   [ (r1, r2) | r1 <- rankings, r2 <- rankings, r1 > r2 ]
    -- ordered pairs

genRankOrdsCo :: Gen (Ranking, Ranking)
genRankOrdsCo = elements ordsCo
  where
    ordsCo = [ (r1, r2) | r1 <- rankings, r2 <- rankings, r1 <= r2 ]
    -- complement pairs

-----

newtype AKey = AKey Key deriving Show

instance Arbitrary AKey where
  arbitrary = AKey <$> (Key <$> elements domainList <*> elements [A, NS, AAAA] <*> pure DNS.classIN)

newtype AWrongCRPair = AWrongCRPair (Key, CRSet) deriving Show

instance Arbitrary AWrongCRPair where
  arbitrary = AWrongCRPair <$> genWrongCRPair

newtype ATTL = ATTL TTL deriving Show

instance Arbitrary ATTL where
  arbitrary = ATTL <$> genTTL

newtype ACRPair = ACRPair (Key, CRSet) deriving Show

instance Arbitrary ACRPair where
  arbitrary = ACRPair <$> genCRPair

newtype ARanking = ARanking Ranking deriving Show

instance Arbitrary ARanking where
  arbitrary = ARanking <$> genRanking

newtype ATimestamp = ATimestamp Timestamp deriving Show

instance Arbitrary ATimestamp where
  arbitrary = ATimestamp <$> genTimestamp

newtype AUpdates = AUpdates [(Timestamp, Update)] deriving Show

instance Arbitrary AUpdates where
  arbitrary = AUpdates <$> genUpdates

newtype ARankOrds = ARankOrds (Ranking, Ranking) deriving Show

instance Arbitrary ARankOrds where
  arbitrary = ARankOrds <$> genRankOrds

newtype ARankOrdsCo = ARankOrdsCo (Ranking, Ranking) deriving Show

instance Arbitrary ARankOrdsCo where
  arbitrary = ARankOrdsCo <$> genRankOrdsCo

newtype ACR2 = ACR2 (Key, (CRSet, CRSet)) deriving Show

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
rrsetTakeNothing (AWrongCRPair (k, crs)) (ATTL ttl) = takeRRSet (extractRRSet k ttl crs) === Nothing

-- forall ((k, crs) :: ACRPair) ttl . takeRRSet (extractRRSet k ttl crs) == Just ((k, ttl), crs)
rrsetExtractTake :: ACRPair -> ATTL  -> Property
rrsetExtractTake (ACRPair (k, crs)) (ATTL ttl) = takeRRSet (extractRRSet k ttl crs) === Just ((k, ttl), crs)

---

-- cache size

-- Cache.size Cache.empty == 0
sizeEmpty :: Property
sizeEmpty = once $ Cache.size Cache.empty === 0

-- size of cache after new key is inserted
sizeNewInserted :: ACRPair -> ATTL -> ARanking -> AUpdates -> Property
sizeNewInserted (ACRPair (k, crs)) (ATTL ttl_) (ARanking rank) (AUpdates us) =
  maybe (property False) checkSize
  $ Cache.insert ts0 k ttl_ crs rank rcache
  where
    checkSize ins = Cache.size ins === Cache.size rcache + 1
    rcache = foldUpdates (removeKeyUpdates k us) Cache.empty  -- 挿入する Key を除去

-- forall ((k, crs) :: ACRPair) ttl cache rs . (rs == extractRRSet k ttl crs) ->
-- (       member k cache  -> size inserted == size cache   \/
--    not (member k cache) -> size inserted == size cache + 1 )
sizeInserted :: ACRPair -> ATTL -> ARanking -> AUpdates -> Property
sizeInserted (ACRPair (k@(Key dom typ cls), crs)) (ATTL ttl_) (ARanking rank) (AUpdates us) =
  maybe (property Discard) checkSize
  $ Cache.insert ts0 k ttl_ crs rank cache
  where
    checkSize ins
      | Cache.member ts0 dom typ cls cache  =  Cache.size ins === Cache.size cache
      | otherwise                           =  Cache.size ins === Cache.size cache + 1
    cache = foldUpdates us Cache.empty

sizeExpire1MinKey :: AUpdates -> Property
sizeExpire1MinKey (AUpdates us) =
  maybe (property Discard) checkSize $ Cache.minKey cache
  where
    cache = foldUpdates us Cache.empty
    checkSize (_, minTS) =
      ( (+ 1) . Cache.size <$> Cache.expire1 minTS cache ) === Just (Cache.size cache)

---

-- lookup

lookupEmpty :: AKey -> Property
lookupEmpty (AKey (Key dom typ cls)) = Cache.lookup ts0 (toDomain dom) typ cls Cache.empty === Nothing

-- lookup key cache after inserted as new key
lookupNewInserted :: ACRPair -> ATTL -> ARanking -> AUpdates -> Property
lookupNewInserted (ACRPair (k@(Key dom typ cls), crs)) (ATTL ttl_) (ARanking rank) (AUpdates us)  =
  (Cache.lookup ts0 (toDomain dom) typ cls =<< Cache.insert ts0 k ttl_ crs rank rcache)
  =/=
  Nothing
  where
    rcache = foldUpdates (removeKeyUpdates k us) Cache.empty  -- 挿入する Key を除去

lookupInserted :: ACRPair -> ATTL -> ARanking -> AUpdates -> Property
lookupInserted (ACRPair (k@(Key dom typ cls), crs)) (ATTL ttl_) (ARanking rank) (AUpdates us)  =
  case Cache.insert ts0 k ttl_ crs rank cache of
    Nothing   ->  label "old" $ Cache.lookup ts0 (toDomain dom) typ cls cache =/= Nothing
    Just ins  ->  label "new" $ Cache.lookup ts0 (toDomain dom) typ cls ins   =/= Nothing
  where
    cache = foldUpdates us Cache.empty

lookupTTL :: ACRPair -> ATTL -> ARanking -> ATimestamp -> AUpdates -> Property
lookupTTL (ACRPair (k@(Key dom typ cls), crs)) (ATTL ttl_) (ARanking rank) (ATimestamp ts1) (AUpdates us)  =
  maybe (property Discard) checkTTL
  $ Cache.insert ts0 k ttl_ crs rank rcache
  where
    rcache = foldUpdates (removeKeyUpdates k us) Cache.empty  -- 挿入する Key を除去
    checkTTL ins =
      case map DNS.rrttl . fst <$> Cache.lookup ts1 (toDomain dom) typ cls ins of
        Nothing    ->  life === Nothing
        Just ttls  ->  Just ttls === (replicate (length ttls) <$> life)
      where
        life = Cache.alive ts1 (ts0 <+ ttl_)

---

-- ranking

rankingOrdered :: ACR2 -> ATTL -> ATTL ->  ARankOrds -> AUpdates -> Property
rankingOrdered (ACR2 (k@(Key dom typ cls), (crs1, crs2))) (ATTL ttl1) (ATTL ttl2) (ARankOrds (r1, r2)) (AUpdates us) =
  maybe (property False) id action
  where
    rcache = foldUpdates (removeKeyUpdates k us) Cache.empty  -- 挿入する Key を除去
    action = do
      c2 <- Cache.insert ts0 k ttl2 crs2 r2 rcache
      c1 <- Cache.insert ts0 k ttl1 crs1 r1 c2
      (rrs, rank) <- Cache.lookup ts0 (toDomain dom) typ cls c1
      return $ rrs === extractRRSet k ttl1 crs1 .&&. rank === r1

rankingNotOrdered :: ACR2 -> ATTL -> ATTL ->  ARankOrdsCo -> AUpdates -> Property
rankingNotOrdered (ACR2 (k, (crs1, crs2))) (ATTL ttl1) (ATTL ttl2) (ARankOrdsCo (r1, r2)) (AUpdates us) =
  action === Nothing
  where
    rcache = foldUpdates (removeKeyUpdates k us) Cache.empty  -- 挿入する Key を除去
    action = do
      c2 <- Cache.insert ts0 k ttl2 crs2 r2 rcache
      _  <- Cache.insert ts0 k ttl1 crs1 r1 c2
      pure ()

---

-- expires

expiresAlives :: AUpdates -> ATimestamp -> Property
expiresAlives (AUpdates us) (ATimestamp ts1) =
  maybe (property Discard) checkSize
  $ Cache.expires ts1 cache
  where
    checkSize ex =
      Cache.size ex
      ===
      length
      [ k | (k, ts) <- Cache.dumpKeys cache, Just _  <- [Cache.alive ts1 ts] ]
    cache = foldUpdates (removeExpiresUpdates us) Cache.empty

expiresMaxEOL :: AUpdates -> Property
expiresMaxEOL (AUpdates us) =
  maybe (property Discard) (=== 0) $ do
  mx <- maxEOL
  c  <- Cache.expires mx cache
  return $ Cache.size c
  where
    cache = foldUpdates us Cache.empty
    eol :: (Timestamp, Update) -> Maybe Timestamp
    eol (ts, I _ ttl _)  =  Just $ ts <+ ttl
    eol ( _,  E)         =  Nothing
    maxEOL = case mapMaybe eol us of
      []        ->  Nothing
      es@(_:_)  ->  Just $ maximum es

-----

props :: [Property]
props =
  [ nprop "RRSet - take nothing"            rrsetTakeNothing
  , nprop "RRSet - extract . take is just"  rrsetExtractTake

  , nprop "size - empty"                    sizeEmpty
  , nprop "size - new inserted"             sizeNewInserted
  , nprop "size - inserted"                 sizeInserted
  , nprop "size - expire1 with min-key"     sizeExpire1MinKey

  , nprop "lookup - empty"                  lookupEmpty
  , nprop "lookup - new inserted"           lookupNewInserted
  , nprop "lookup - inserted"               lookupInserted
  , nprop "lookup - ttl"                    lookupTTL

  , nprop "ranking - ordered"               rankingOrdered
  , nprop "ranking - not ordered"           rankingNotOrdered

  , nprop "expires - alives"                expiresAlives
  , nprop "expires - with max EOL"          expiresMaxEOL
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
