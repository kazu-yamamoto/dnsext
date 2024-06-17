{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Verify (
    -- * case split for RRSIG verification
    cases,
    cases',
    -- * RRSIG, sep DNSKEY verification, for tests
    rrWithRRSIG,
    sepDNSKEY,
    -- * NSEC / NSEC3 verification
    NResultK,
    GetNE,
    GetNoDatas,
    getNameError,
    getUnsignedDelegation,
    getWildcardExpansion,
    getNoDatas,
    -- * low-level, NSEC / NSEC3 verification
    GetResult,
    runHandlers,
    mkHandler,
    nsecWithValid,
    nsec3WithValid,
) where

-- GHC packages

-- other packages

-- dnsext packages
import qualified DNS.Log as Log
import DNS.RRCache (Ranking)
import qualified DNS.RRCache as Cache
import DNS.SEC
import qualified DNS.SEC.Verify as SEC
import DNS.SEC.Verify.Types
import DNS.Types
import qualified DNS.Types as DNS
import qualified DNS.Types.Internal as DNS
import System.Console.ANSI.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils

{- FOURMOLU_DISABLE -}
-- |
-- null case is no RR for specified type.
-- nc case is not canonical RRset.
-- right case is after verified, with valid or invalid RRset.
cases
    :: (MonadIO m, MonadReader Env m)
    => IO EpochTime
    -> Domain
    -> [RD_DNSKEY]
    -> (dm -> ([ResourceRecord], Ranking)) -> dm
    -> Domain  -> TYPE
    -> (ResourceRecord -> Maybe a)
    -> m b -> (m () -> m b)
    -> ([a] -> RRset -> m () -> m b)
    -> m b
cases getSec zone dnskeys getRanked msg rrn rrty h nullK ncK rightK =
    withSection getRanked msg $ \srrs rank -> cases' getSec zone dnskeys srrs rank rrn rrty h nullK ncK rightK
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
cases'
    :: (MonadIO m, MonadReader Env m)
    => IO EpochTime
    -> Domain
    -> [RD_DNSKEY]
    -> [ResourceRecord] -> Ranking
    -> Domain -> TYPE
    -> (ResourceRecord -> Maybe a)
    -> m b -> (m () -> m b)
    -> ([a] -> RRset -> m () -> m b)
    -> m b
cases' getSec zone dnskeys srrs rank rrn rrty h nullK ncK0 rightK0
    | null xRRs = nullK
    | otherwise = canonicalRRset xRRs (ncK xRRs) rightK
  where
    ncK rrs s = ncK0 $ logLines Log.WARN (("not canonical RRset: " ++ s) : map (("\t" ++) . show) rrs)
    (fromRDs, xRRs) = unzip [(x, rr) | rr <- srrs, rrtype rr == rrty, Just x <- [h rr], rrname rr == rrn]
    sigs = rrsigList zone rrn rrty srrs
    verifiedK rrset@(RRset dom typ cls minTTL rds sigrds) = rightK0 fromRDs rrset (logInv *> cache)
      where
        cache = cacheRRset rank dom typ cls minTTL rds sigrds
        logInv = mayVerifiedRRS (pure ()) (logInvalids . lines) (const $ pure ()) $ rrsMayVerified rrset
        logInvalids  []    = clogLn Log.DEMO (Just Cyan)  "cases: InvalidRRS"
        logInvalids (e:es) = clogLn Log.DEMO (Just Cyan) ("cases: InvalidRRS: " ++ e) *> logLines Log.DEMO es
    rightK rrset sortedRRs = do
        now <- liftIO getSec
        withVerifiedRRset now dnskeys rrset sortedRRs sigs verifiedK
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
withVerifiedRRset
    :: EpochTime
    -> [RD_DNSKEY]
    -> RRset -> [(Int, DNS.Builder ())] -> [(RD_RRSIG, TTL)]
    -> (RRset -> a)
    -> a
withVerifiedRRset now dnskeys0 RRset{..} sortedRDatas sigs0 vk =
    vk $ RRset rrsName rrsType rrsClass minTTL rrsRDatas mayVerified
  where
    noverify = (rrsTTL, NotVerifiedRRS)
    invalid err = (rrsTTL, InvalidRRS err)
    valid goodSigs = (minimum $ rrsTTL : sigTTLs ++ map fromIntegral expireTTLs, ValidRRS sigrds)
      where
        (sigrds, sigTTLs) = unzip goodSigs
        expireTTLs = [exttl | sig <- sigrds, let exttl = fromDNSTime (rrsig_expiration sig) - now, exttl > 0]

    (minTTL, mayVerified) = rrWithRRSIG' now dnskeys0 rrsName rrsType rrsClass sortedRDatas sigs0 noverify invalid valid
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
rrWithRRSIG
    :: EpochTime -> [RD_DNSKEY] ->  [ResourceRecord] -> [(RD_RRSIG, a)]
    -> b -> (String -> b) -> ([(RD_RRSIG, a)] -> b) -> b
rrWithRRSIG now dnskeys0 rrs sigs0 noverify left right = canonicalRRset rrs left cn
  where
    cn RRset{..} sortedRDatas = rrWithRRSIG' now dnskeys0 rrsName rrsType rrsClass sortedRDatas sigs0 noverify left right
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
rrWithRRSIG'
    :: EpochTime -> [RD_DNSKEY]
    -> Domain -> TYPE -> CLASS -> [(Int, DNS.Builder ())] -> [(RD_RRSIG, a)]
    -> b -> (String -> b) -> ([(RD_RRSIG, a)] -> b) -> b
rrWithRRSIG' now dnskeys0 name typ cls sortedRDatas sigs0 noverify left right = result
  where
    (supKeys, unsupKeys) = partition (SEC.supportedDNSKEY . fst) [(k, SEC.keyTag k) | k <- dnskeys0]
    (usedKeys, unusedKeys0) = splitAt rejectLimit supKeys
    dnskeySortKey = (,) <$> dnskey_pubalg . fst <*> snd
    keySets = limitSortedGroupBy collisionLimit dnskeySortKey usedKeys  {- limit keys which have collided keytag -}

    (supSigs, unsupSigs) = partition (SEC.supportedRRSIG . fst) sigs0
    (usedSigs, unusedSigs0) = splitAt rejectLimit supSigs
    rrsigSortKey = (,) <$> rrsig_pubalg <*> rrsig_key_tag
    sigSets = limitSortedGroupBy collisionLimit (rrsigSortKey . fst) usedSigs  {- limit sigs which have same keytag -}

    keySigSets = matchSortedGroup dnskeySortKey (rrsigSortKey . fst) keySets sigSets
    unusedKeys = unusedKeys0 ++ [k | MLeft  ks <- keySigSets, k <- ks] ++ unsupKeys
    unusedSigs = unusedSigs0 ++ [s | MRight ss <- keySigSets, s <- ss] ++ unsupSigs

    verify key sigrd = SEC.verifyRRSIGsorted (toDNSTime now) key sigrd name typ cls sortedRDatas
    verifies = take rejectLimit $  {- limit number of verifications -}
        [ (verify keyrd sigrd, key, sig)
        | Match (dnskeys, sigs) <- keySigSets
        , sig@(sigrd, _) <- sigs
        , key@(keyrd, _) <- dnskeys
        ]

    goodSigs = [sig | (Right (), _, sig) <- verifies]

    showSig sigrd = "rrsig: " ++ show sigrd
    showKey key keyTag = "dnskey: " ++ show key ++ " (key_tag: " ++ show keyTag ++ ")"
    showUnusedKeysSigs =
        [showKey key tag | (key, tag) <- take showLimit unusedKeys] ++ [".." | length unusedKeys > showLimit] ++
        [showSig sigrd   | (sigrd, _) <- take showLimit unusedSigs] ++ [".." | length unusedSigs > showLimit]
      where
        showLimit = 5
    verifyErrors =
        [ s
        | (Left em, (key, dnskeyTag), (sigrd, _)) <- verifies
        , s <- ["  error: " ++ em, "    " ++ show sigrd, "    " ++ showKey key dnskeyTag]
        ]
    noValids
        | null verifies    = unlines $ "no-match key-tags or no-supported keys:" : map ("  " ++) showUnusedKeysSigs
        | otherwise        = unlines $ "no good sigs:" : verifyErrors

    result
        | null usedKeys  = noverify {- no way to verify  -}
        | null usedSigs  = left "supported DNSKEYs exist and supported RRSIGs is null" {- dnskeys is not null, but sigs is null -}
        | null goodSigs  = left noValids
        | otherwise      = right goodSigs
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
sepDNSKEY
    :: [RD_DS] -> Domain -> [RD_DNSKEY]
    -> Either String (NonEmpty (RD_DNSKEY, RD_DS))
sepDNSKEY dss0 dom dnskeys0 = do
    let seps = [ (key, ds) | (Right (), key, ds) <- verifies ]
    list (Left "sepkeyDS: no DNSKEY matches with DS") (\s ss -> Right $ s:|ss) seps
  where
    usedkeys = take rejectLimit [(k, SEC.keyTag k) | k <- dnskeys0, SEC.supportedDNSKEY k]
    dnskeySortKey = (,) <$> dnskey_pubalg . fst <*> snd
    keySets = limitSortedGroupBy collisionLimit dnskeySortKey usedkeys

    usedDss = take rejectLimit [ds | ds <- dss0, SEC.supportedDS ds]
    dsSortKey = (,) <$> ds_pubalg <*> ds_key_tag
    dsSets = limitSortedGroupBy collisionLimit dsSortKey usedDss

    keyDsSets = matchSortedGroup dnskeySortKey dsSortKey keySets dsSets
    verifies = take rejectLimit $
        [ (SEC.verifyDS dom key ds, key, ds)
        | Match (dnskeys, dss) <- keyDsSets
        , (key, _) <- dnskeys
        , ds <- dss
        ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
limitSortedGroupBy :: Ord b => Int -> (a -> b) -> [a] -> [[a]]
limitSortedGroupBy colLimit sortKey = map (take colLimit) . groupBy ((==) `on` sortKey) . sortOn sortKey
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data Match a b
    = MLeft  a
    | Match (a, b)
    | MRight b
    deriving Show

-- |
-- >>> matchSortedGroup id id [[1], [2], [4], [6], [7]] [[1], [3], [4], [5], [7]] :: [Match [Int] [Int]]
-- [Match ([1],[1]),MLeft [2],MRight [3],Match ([4],[4]),MRight [5],MLeft [6],Match ([7],[7])]
-- >>> matchSortedGroup id id [[1], [2], [4], [6], [7], [9]] [[1], [3], [4], [5], [7]] :: [Match [Int] [Int]]
-- [Match ([1],[1]),MLeft [2],MRight [3],Match ([4],[4]),MRight [5],MLeft [6],Match ([7],[7]),MLeft [9]]
-- >>> matchSortedGroup id id [[1], [2], [4], [6], [7]] [[1], [3], [4], [5], [7], [8]] :: [Match [Int] [Int]]
-- [Match ([1],[1]),MLeft [2],MRight [3],Match ([4],[4]),MRight [5],MLeft [6],Match ([7],[7]),MRight [8]]
matchSortedGroup :: Ord a => (k -> a) -> (s -> a) -> [[k]] -> [[s]] -> [Match [k] [s]]
matchSortedGroup kx ky = merge (kx . head) (ky . head) left right pair
  where
    left  x    = (MLeft x     :)
    right y    = (MRight y    :)
    pair  x y  = (Match (x,y) :)
{- FOURMOLU_ENABLE -}

rejectLimit :: Int
rejectLimit = 16

collisionLimit :: Int
collisionLimit = 4

---

type NResultK r m a = r -> [RRset] -> m () -> a

{- FOURMOLU_DISABLE -}
type GetNE m msg r1 r2 a
    =  Domain -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> Domain
    -> m a -> (String -> m a) -> (String -> m a)
    -> NResultK r1 m (m a) -> NResultK r2 m (m a)
    -> m a

type GetNoDatas m msg r1 r2 r3 r4 a
    =  Domain -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> Domain -> TYPE
    -> m a -> (String -> m a) -> (String -> m a)
    -> NResultK r1 m (m a) -> NResultK r2 m (m a) -> NResultK r3 m (m a) -> NResultK r4 m (m a)
    -> m a
{- FOURMOLU_ENABLE -}

getNameError :: (MonadIO m, MonadReader Env m) => GetNE m msg NSEC_NameError NSEC3_NameError a
getNameError zone dnskeys getRanked msg qname =
    getWithFallback (\rs -> SEC.nameErrorNSEC zone rs qname) (\rs -> SEC.nameErrorNSEC3 zone rs qname) dnskeys getRanked msg

getUnsignedDelegation :: (MonadIO m, MonadReader Env m) => GetNE m msg NSEC_UnsignedDelegation NSEC3_UnsignedDelegation a
getUnsignedDelegation zone dnskeys getRanked msg qname =
    getWithFallback
        (\rs -> SEC.unsignedDelegationNSEC zone rs qname)
        (\rs -> SEC.unsignedDelegationNSEC3 zone rs qname)
        dnskeys
        getRanked
        msg

getWildcardExpansion :: (MonadIO m, MonadReader Env m) => GetNE m msg NSEC_WildcardExpansion NSEC3_WildcardExpansion a
getWildcardExpansion zone dnskeys getRanked msg qname =
    getWithFallback
        (\rs -> SEC.wildcardExpansionNSEC zone rs qname)
        (\rs -> SEC.wildcardExpansionNSEC3 zone rs qname)
        dnskeys
        getRanked
        msg

---

type GetResult range r = [range] -> Either String r

{- FOURMOLU_DISABLE -}
getWithFallback
    :: (MonadIO m, MonadReader Env m)
    => GetResult NSEC_Range nsecr -> GetResult NSEC3_Range nsec3r
    -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> m a -> (String -> m a) -> (String -> m a)
    -> NResultK nsecr m (m a) -> NResultK nsec3r m (m a)
    -> m a
getWithFallback getNSEC getNSEC3 dnskeys getRanked msg nullK invalidK leftK rightNSEC rightNSEC3 = nsec
  where
    nsec  = nsecWithValid   dnskeys getRanked msg nullNSEC invalidK nsecK
    nullNSEC = nsec3
    nsecK  ranges rrsets doCache =
        runHandlers "cannot handle NSEC:" leftK $
        handle getNSEC   rightNSEC
      where
        handle = mkHandler ranges rrsets doCache

    nsec3 = nsec3WithValid  dnskeys getRanked msg nullK    invalidK nsec3K
    nsec3K ranges rrsets doCache =
        runHandlers "cannot handle NSEC3:" leftK $
        handle getNSEC3  rightNSEC3
      where
        handle = mkHandler ranges rrsets doCache
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
getNoDatas :: (MonadIO m, MonadReader Env m) => GetNoDatas m msg NSEC_WildcardNoData NSEC_NoData NSEC3_WildcardNoData NSEC3_NoData a
getNoDatas zone dnskeys getRanked msg qname qtype nullK invalidK leftK rightNSECwild rightNSEC rightNSEC3wild rightNSEC3 = nsec
  where
    nsec  = nsecWithValid   dnskeys getRanked msg nullNSEC invalidK nsecK
    nullNSEC = nsec3
    nsecK  ranges rrsets doCache =
        runHandlers "cannot handle NSEC NoDatas:" leftK $
        handle wildcardNoData rightNSECwild .
        handle noData         rightNSEC
      where
        handle = mkHandler ranges rrsets doCache
        wildcardNoData rs  = SEC.wildcardNoDataNSEC   zone rs qname qtype
        noData         rs  = SEC.noDataNSEC           zone rs qname qtype

    nsec3 = nsec3WithValid  dnskeys getRanked msg nullK    invalidK nsec3K
    nsec3K ranges rrsets doCache =
        runHandlers "cannot handle NSEC3 NoDatas:" leftK $
        handle wildcardNoData rightNSEC3wild .
        handle noData         rightNSEC3
      where
        handle = mkHandler ranges rrsets doCache
        wildcardNoData rs  = SEC.wildcardNoDataNSEC3  zone rs qname qtype
        noData         rs  = SEC.noDataNSEC3          zone rs qname qtype
{- FOURMOLU_ENABLE -}

---

runHandlers :: String -> (String -> a) -> ((String -> a) -> String -> a) -> a
runHandlers header leftK h = h leftK (header ++ ":\n")

{- FOURMOLU_DISABLE -}
mkHandler
    :: [range]
    -> [RRset]
    -> m ()
    ---
    -> GetResult range r
    -> NResultK r m a
    ---
    -> (String -> a)
    -> (String -> a)
mkHandler ranges rrsets doCache getR resultK fallbackK = case getR ranges of
    Right r  -> \_ -> resultK r rrsets doCache
    Left e   -> fallbackK . (++ ("  " ++ e))
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
nsecWithValid
    :: (MonadIO m, MonadReader Env m)
    => [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> m a -> (String -> m a)
    -> ([NSEC_Range] -> [RRset] -> m () -> m a)
    -> m a
{- FOURMOLU_ENABLE -}
nsecWithValid = nsecxWithValid SEC.zipSigsNSEC "NSEC"

{- FOURMOLU_DISABLE -}
nsec3WithValid
    :: (MonadIO m, MonadReader Env m)
    => [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> m a -> (String -> m a)
    -> ([NSEC3_Range] -> [RRset] -> m () -> m a)
    -> m a
{- FOURMOLU_ENABLE -}
nsec3WithValid = nsecxWithValid SEC.zipSigsNSEC3 "NSEC3"

type WithZippedSigs r a = [ResourceRecord] -> (String -> a) -> ([(ResourceRecord, r, [(RD_RRSIG, TTL)])] -> a) -> a

{- FOURMOLU_DISABLE -}
nsecxWithValid
    :: (MonadIO m, MonadReader Env m)
    => WithZippedSigs range (m a) -> String
    -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> m a -> (String -> m a)
    -> ([range] -> [RRset] -> m () -> m a)
    -> m a
{- FOURMOLU_ENABLE -}
nsecxWithValid withZippedSigs tag dnskeys getRanked msg nullK invalidK validK0 =
    nsecxWithValid' withZippedSigs tag dnskeys getRanked msg nullK ncK invalidK validK
  where
    ncK = invalidK . ("not canonical NSEC/NSEC3, something wrong: " ++)
    validK = uncurry validK0 . unzip

{- FOURMOLU_DISABLE -}
nsecxWithValid'
    :: (MonadIO m, MonadReader Env m)
    => WithZippedSigs range (m a) -> String
    -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> m a -> (String -> m a) -> (String -> m a)
    -> ([(range, RRset)] -> m () -> m a)
    -> m a
{- FOURMOLU_ENABLE -}
nsecxWithValid' withZippedSigs tag dnskeys getRanked msg nullK ncK invalidK validK =
    nsecxWithRanges withZippedSigs dnskeys getRanked msg nullK ncK runVerified
  where
    runVerified rps doCache
        | valid = validK rps doCache
        | otherwise = invalidK $ unlines notValidErrors
      where
        (_ranges, rrsets) = unzip rps
        valid = all rrsetValid rrsets

        notValidErrors = header : esInvalid ++ esNotVerified
        header = tag ++ " verify errors: "
        esInvalid = [ie | set <- rrsets, InvalidRRS ie <- [rrsMayVerified set]]
        esNotVerified = "not-verified RRset list:" : ["  " ++ showRRset set | set <- rrsets, NotVerifiedRRS <- [rrsMayVerified set]]
        showRRset RRset{..} = unwords [show rrsName, show rrsType, show rrsRDatas]

{- FOURMOLU_DISABLE -}
nsecxWithRanges
    :: (MonadIO m, MonadReader Env m)
    => WithZippedSigs range (m a)
    -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> m a -> (String -> m a)
    -> ([(range, RRset)] -> m () -> m a)
    -> m a
{- FOURMOLU_ENABLE -}
nsecxWithRanges withZippedSigs dnskeys getRanked msg nullK leftK rightK = do
    now <- liftIO =<< asks currentSeconds_
    withSection getRanked msg $ runSection now
  where
    runSection now srrs rank = withZippedSigs srrs leftK $ runSigned now rank

    runSigned _now _rank [] = nullK
    runSigned now rank rs@(_ : _) = either leftK (runVerified rank) $ mapM (verify now) rs

    runVerified rank vs = rightK vs $ doCache rank vs

    {- TODO: interval search psq cache -}
    doCache _rank vs = mapM_ (\(_range, _rrset@(RRset{})) -> pure ()) vs

    verify now (rr, range, sigs) =
        canonicalRRset [rr] Left $ \rrset sortedRDatas ->
            Right $ withVerifiedRRset now dnskeys rrset sortedRDatas sigs ((,) range)

---

{- get not verified canonical RRset -}
canonicalRRset :: [ResourceRecord] -> (String -> a) -> (RRset -> [(Int, DNS.Builder ())] -> a) -> a
canonicalRRset rrs leftK rightK =
    SEC.canonicalRRsetSorted' sortedRRs leftK mkRRset
  where
    mkRRset dom typ cls ttl rds = rightK (RRset dom typ cls ttl rds NotVerifiedRRS) sortedRDatas
    (sortedRDatas, sortedRRs) = unzip $ SEC.sortRDataCanonical rrs

cacheRRset
    :: (MonadIO m, MonadReader Env m)
    => Ranking
    -> Domain
    -> TYPE
    -> CLASS
    -> TTL
    -> [RData]
    -> MayVerifiedRRS
    -> m ()
cacheRRset rank dom typ cls ttl rds mv =
    mayVerifiedRRS notVerivied (const $ pure ()) valid mv
  where
    notVerivied = Cache.notVerified rds (pure ()) doCache
    valid sigs = Cache.valid rds sigs (pure ()) doCache
    doCache crs = do
        insertRRSet <- asks insert_
        logLn Log.DEBUG $ "cacheRRset: " ++ show (((dom, typ, cls), ttl), rank) ++ "  " ++ show rds
        liftIO $ insertRRSet (DNS.Question dom typ cls) ttl crs rank
