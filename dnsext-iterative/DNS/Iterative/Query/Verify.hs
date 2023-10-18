{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Verify (
    with,
    withCanonical,
    withCanonical',
    --
    NResultK,
    GetNE,
    GetNoDatas,
    getNameError,
    getNameError',
    getUnsignedDelegation,
    getUnsignedDelegation',
    getWildcardExpansion,
    getWildcardExpansion',
    getNoDatas,
    getNoDatas',
    --
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

-- |
-- null case is no RR for specified type.
-- left case is not canonical RRset.
-- righ case is after verified, with valid or invalid RRset.
{- FOURMOLU_DISABLE -}
with
    :: [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking)) -> m
    -> Domain -> TYPE
    -> (ResourceRecord -> Maybe a)
    -> DNSQuery b -> DNSQuery b -> ([a] -> RRset -> ContextT IO () -> DNSQuery b)
    -> DNSQuery b
{- FOURMOLU_ENABLE -}
with dnskeys getRanked msg rrn rrty h nullK leftK rightK = do
    let rightK' xs rrset cache = pure $ rightK xs rrset cache
    action <- lift $ withCanonical dnskeys getRanked msg rrn rrty h (pure nullK) (pure leftK) rightK'
    action

{- FOURMOLU_DISABLE -}
withCanonical
    :: [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking)) -> m
    -> Domain  -> TYPE
    -> (ResourceRecord -> Maybe a)
    -> ContextT IO b -> ContextT IO b -> ([a] -> RRset -> ContextT IO () -> ContextT IO b)
    -> ContextT IO b
{- FOURMOLU_ENABLE -}
withCanonical dnskeys getRanked msg rrn rrty h nullK leftK rightK =
    withSection getRanked msg $ \srrs rank -> withCanonical' dnskeys rrn rrty h srrs rank nullK ncK withRRS
  where
    ncK rrs s = logLines Log.WARN (("not canonical RRset: " ++ s) : map (("\t" ++) . show) rrs) *> leftK
    withRRS x rrset cache = do
        mayVerifiedRRS (pure ()) logInvalids (const $ pure ()) $ rrsMayVerified rrset
        rightK x rrset cache
    logInvalids es = do
        (x, xs) <- pure $ case lines es of
            [] -> ("", [])
            x : xs -> (": " ++ x, xs)
        clogLn Log.DEMO (Just Cyan) $ "withCanonical: InvalidRRS" ++ x
        logLines Log.DEMO xs

{- FOURMOLU_DISABLE -}
withCanonical'
    :: [RD_DNSKEY]
    -> Domain -> TYPE
    -> (ResourceRecord -> Maybe a)
    -> [ResourceRecord] -> Ranking
    -> ContextT IO b -> ([ResourceRecord] -> String -> ContextT IO b)
    -> ([a] -> RRset -> ContextT IO () -> ContextT IO b)
    -> ContextT IO b
{- FOURMOLU_ENABLE -}
withCanonical' dnskeys rrn rrty h srrs rank nullK leftK rightK0
    | null xRRs = nullK
    | otherwise = canonicalRRset xRRs (leftK xRRs) rightK
  where
    (fromRDs, xRRs) = unzip [(x, rr) | rr <- srrs, rrtype rr == rrty, Just x <- [h rr], rrname rr == rrn]
    sigs = rrsigList rrn rrty srrs
    rightK rrs sortedRRs = do
        now <- liftIO =<< asks currentSeconds_
        withVerifiedRRset now dnskeys rrs sortedRRs sigs $ \rrset@(RRset dom typ cls minTTL rds sigrds) ->
            rightK0 fromRDs rrset (cacheRRset rank dom typ cls minTTL rds sigrds)

{- FOURMOLU_DISABLE -}
withVerifiedRRset
    :: EpochTime
    -> [RD_DNSKEY]
    -> RRset -> [(Int, DNS.Builder ())] -> [(RD_RRSIG, TTL)]
    -> (RRset -> a)
    -> a
{- FOURMOLU_ENABLE -}
withVerifiedRRset now dnskeys RRset{..} sortedRDatas sigs vk =
    vk $ RRset rrsName rrsType rrsClass minTTL rrsRDatas goodSigRDs
  where
    expireTTLs = [exttl | sig <- sigrds, let exttl = fromDNSTime (rrsig_expiration sig) - now, exttl > 0]
    minTTL = minimum $ rrsTTL : sigTTLs ++ map fromIntegral expireTTLs
    verify key sigrd = SEC.verifyRRSIGsorted (toDNSTime now) key sigrd rrsName rrsType rrsClass sortedRDatas
    goodSigs =
        [ rrsig
        | rrsig@(sigrd, _) <- sigs
        , key <- dnskeys
        , Right () <- [verify key sigrd]
        ]
    (sigrds, sigTTLs) = unzip goodSigs
    goodSigRDs
        | null dnskeys = NotVerifiedRRS {- no way to verify  -}
        | null sigs = InvalidRRS "DNSKEYs exist and RRSIGs is null" {- dnskeys is not null, but sigs is null -}
        | null sigrds = InvalidRRS noValids {- no good signatures -}
        | otherwise = ValidRRS sigrds
    noValids
        | null verifyErrors = unlines $ "no match key-tags:" : map ("  " ++) showKeysSigs
        | otherwise = unlines $ "no good sigs:" : verifyErrors
    showKeysSigs = [showKey key (SEC.keyTag key) | key <- dnskeys] ++ [showSig sigrd | (sigrd, _) <- sigs]
    verifyErrors =
        [ s
        | (sigrd, _) <- sigs
        , key <- dnskeys
        , let dnskeyTag = SEC.keyTag key
        , dnskeyTag == rrsig_key_tag sigrd
        , Left em <- [verify key sigrd]
        , s <- ["  error: " ++ em, "    " ++ show sigrd, "    " ++ showKey key dnskeyTag]
        ]
    showSig sigrd = "rrsig: " ++ show sigrd
    showKey key keyTag = "dnskey: " ++ show key ++ " (key_tag: " ++ show keyTag ++ ")"

---

type NResultK r a = r -> [RRset] -> ContextT IO () -> a

{- FOURMOLU_DISABLE -}
type GetNE m msg r1 r2 a
    =  Domain -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> Domain
    -> m a -> (String -> m a) -> (String -> m a)
    -> NResultK r1 (m a) -> NResultK r2 (m a)
    -> m a

type GetNoDatas m msg r1 r2 r3 r4 a
    =  Domain -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> Domain -> TYPE
    -> m a -> (String -> m a) -> (String -> m a)
    -> NResultK r1 (m a) -> NResultK r2 (m a) -> NResultK r3 (m a) -> NResultK r4 (m a)
    -> m a
{- FOURMOLU_ENABLE -}

getNameError :: GetNE DNSQuery m NSEC_NameError NSEC3_NameError a
getNameError = liftN2 getNameError'

getUnsignedDelegation :: GetNE DNSQuery m NSEC_UnsignedDelegation NSEC3_UnsignedDelegation a
getUnsignedDelegation = liftN2 getUnsignedDelegation'

getWildcardExpansion :: GetNE DNSQuery m NSEC_WildcardExpansion NSEC3_WildcardExpansion a
getWildcardExpansion = liftN2 getWildcardExpansion'

getNoDatas :: GetNoDatas DNSQuery m NSEC_WildcardNoData NSEC_NoData NSEC3_WildcardNoData NSEC3_NoData a
getNoDatas = liftNoData getNoDatas'

{- FOURMOLU_DISABLE -}
liftN2 :: GetNE (ContextT IO) m r1 r2 (DNSQuery a) -> GetNE DNSQuery m r1 r2 a
liftN2 getN2 zone dnskeys getRanked msg qname nullK notValidK leftK rightK1 rightK2 = do
    let liftR rightK r rrsets cache = pure $ rightK r rrsets cache
    action <- lift $ getN2 zone dnskeys getRanked msg qname
              (pure nullK) (pure . notValidK) (pure . leftK) (liftR rightK1) (liftR rightK2)
    action

liftNoData :: GetNoDatas (ContextT IO) m r1 r2 r3 r4 (DNSQuery a) -> GetNoDatas DNSQuery m r1 r2 r3 r4 a
liftNoData getND zone dnskeys getRanked msg qname qtype nullK notValidK leftK rightK1 rightK2 rightK3 rightK4 = do
    let liftR rightK r rrsets cache = pure $ rightK r rrsets cache
    action <- lift $ getND zone dnskeys getRanked msg qname qtype
              (pure nullK) (pure . notValidK) (pure . leftK) (liftR rightK1) (liftR rightK2) (liftR rightK3) (liftR rightK4)
    action
{- FOURMOLU_ENABLE -}

getNameError' :: GetNE (ContextT IO) m NSEC_NameError NSEC3_NameError a
getNameError' zone dnskeys getRanked msg qname =
    getWithFallback (\rs -> SEC.nameErrorNSEC zone rs qname) (\rs -> SEC.nameErrorNSEC3 zone rs qname) dnskeys getRanked msg

getUnsignedDelegation' :: GetNE (ContextT IO) m NSEC_UnsignedDelegation NSEC3_UnsignedDelegation a
getUnsignedDelegation' zone dnskeys getRanked msg qname =
    getWithFallback
        (\rs -> SEC.unsignedDelegationNSEC zone rs qname)
        (\rs -> SEC.unsignedDelegationNSEC3 zone rs qname)
        dnskeys
        getRanked
        msg

getWildcardExpansion' :: GetNE (ContextT IO) m NSEC_WildcardExpansion NSEC3_WildcardExpansion a
getWildcardExpansion' zone dnskeys getRanked msg qname =
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
    :: GetResult NSEC_Range nsecr -> GetResult NSEC3_Range nsec3r
    -> [RD_DNSKEY]
    -> (msg -> ([ResourceRecord], Ranking)) -> msg
    -> ContextT IO a -> (String -> ContextT IO a) -> (String -> ContextT IO a)
    -> NResultK nsecr (ContextT IO a) -> NResultK nsec3r (ContextT IO a)
    -> ContextT IO a
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
getNoDatas' :: GetNoDatas (ContextT IO) msg NSEC_WildcardNoData NSEC_NoData NSEC3_WildcardNoData NSEC3_NoData a
getNoDatas' zone dnskeys getRanked msg qname qtype nullK invalidK leftK rightNSECwild rightNSEC rightNSEC3wild rightNSEC3 = nsec
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
    -> ContextT IO ()
    ---
    -> GetResult range r
    -> NResultK r a
    ---
    -> (String -> a)
    -> (String -> a)
mkHandler ranges rrsets doCache getR resultK fallbackK = case getR ranges of
    Right r  -> \_ -> resultK r rrsets doCache
    Left e   -> fallbackK . (++ ("  " ++ e))
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
nsecWithValid
    :: [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking)) -> m
    -> ContextT IO a -> (String -> ContextT IO a)
    -> ([NSEC_Range] -> [RRset] -> ContextT IO () -> ContextT IO a)
    -> ContextT IO a
{- FOURMOLU_ENABLE -}
nsecWithValid = nsecxWithValid SEC.zipSigsNSEC "NSEC"

{- FOURMOLU_DISABLE -}
nsec3WithValid
    :: [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking)) -> m
    -> ContextT IO a -> (String -> ContextT IO a)
    -> ([NSEC3_Range] -> [RRset] -> ContextT IO () -> ContextT IO a)
    -> ContextT IO a
{- FOURMOLU_ENABLE -}
nsec3WithValid = nsecxWithValid SEC.zipSigsNSEC3 "NSEC3"

type WithZippedSigs r a = [ResourceRecord] -> (String -> a) -> ([(ResourceRecord, r, [(RD_RRSIG, TTL)])] -> a) -> a

{- FOURMOLU_DISABLE -}
nsecxWithValid
    :: WithZippedSigs range (ContextT IO a) -> String
    -> [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking)) -> m
    -> ContextT IO a -> (String -> ContextT IO a)
    -> ([range] -> [RRset] -> ContextT IO () -> ContextT IO a)
    -> ContextT IO a
{- FOURMOLU_ENABLE -}
nsecxWithValid withZippedSigs tag dnskeys getRanked msg nullK invalidK validK0 =
    nsecxWithValid' withZippedSigs tag dnskeys getRanked msg nullK ncK invalidK validK
  where
    ncK = invalidK . ("not canonical NSEC/NSEC3, something wrong: " ++)
    validK = uncurry validK0 . unzip

{- FOURMOLU_DISABLE -}
nsecxWithValid'
    :: WithZippedSigs range (ContextT IO a) -> String
    -> [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking)) -> m
    -> ContextT IO a -> (String -> ContextT IO a) -> (String -> ContextT IO a)
    -> ([(range, RRset)] -> ContextT IO () -> ContextT IO a)
    -> ContextT IO a
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
    :: WithZippedSigs range (ContextT IO a)
    -> [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking)) -> m
    -> ContextT IO a -> (String -> ContextT IO a)
    -> ([(range, RRset)] -> ContextT IO () -> ContextT IO a)
    -> ContextT IO a
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
    :: Ranking
    -> Domain
    -> TYPE
    -> CLASS
    -> TTL
    -> [RData]
    -> MayVerifiedRRS
    -> ContextT IO ()
cacheRRset rank dom typ cls ttl rds mv =
    mayVerifiedRRS notVerivied (const $ pure ()) valid mv
  where
    notVerivied = Cache.notVerified rds (pure ()) doCache
    valid sigs = Cache.valid rds sigs (pure ()) doCache
    doCache crs = do
        insertRRSet <- asks insert_
        logLn Log.DEBUG $ "cacheRRset: " ++ show (((dom, typ, cls), ttl), rank) ++ "  " ++ show rds
        liftIO $ insertRRSet (DNS.Question dom typ cls) ttl crs rank
