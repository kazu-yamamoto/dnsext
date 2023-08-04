{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Cache (
    lookupValid,
    lookupRRsetEither,
    lookupCache,
    lookupCacheEither,
    cacheAnswer,
    cacheSection,
    cacheNoRRSIG,
    cacheNoDelegation,
) where

-- GHC packages
import Control.Arrow ((>>>))
import Control.Monad (guard)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Reader (asks)
import Data.Function (on)
import Data.Functor (($>), (<&>))
import Data.List (groupBy, sortOn)

-- other packages

import System.Console.ANSI.Types

-- dns packages
import DNS.Do53.Memo (
    Ranking,
    insertSetEmpty,
    rankedAnswer,
    rankedAuthority,
 )
import qualified DNS.Do53.Memo as Cache
import DNS.SEC (
    RD_DNSKEY,
    RD_RRSIG,
    TYPE,
 )
import qualified DNS.SEC.Verify as SEC
import DNS.Types (
    DNSMessage,
    Domain,
    ResourceRecord (..),
    TTL,
    TYPE (CNAME, NS, SOA),
    CLASS,
 )
import qualified DNS.Types as DNS
import DNS.Types.Decode (EpochTime)

-- this package
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Cache.Iterative.Verify as Verify
import qualified DNS.Log as Log

type CacheHandler a = EpochTime -> Domain -> TYPE -> CLASS -> Cache.Cache -> Maybe (a, Ranking)

withLookupCache :: CacheHandler a -> String -> Domain -> TYPE -> ContextT IO (Maybe (a, Ranking))
withLookupCache h logMark dom typ = do
    getCache <- asks getCache_
    getSec <- asks currentSeconds_
    result <- liftIO $ do
        cache <- getCache
        ts <- getSec
        return $ h ts dom typ DNS.classIN cache
    let pprResult = maybe "miss" (\(_, rank) -> "hit: " ++ show rank) result
        mark ws
            | null logMark = ws
            | otherwise = (logMark ++ ":") : ws
    logLn Log.DEBUG . unwords $ "lookupCache:" : mark [show dom, show typ, show DNS.classIN, ":", pprResult]
    return result

lookupRRset :: String -> Domain -> TYPE -> ContextT IO (Maybe (RRset, Ranking))
lookupRRset logMark dom typ = withLookupCache mkAlive logMark dom typ
  where
    mkAlive :: CacheHandler RRset
    mkAlive ts = Cache.lookupAlive ts result
    result ttl crset rank = either (const Nothing) rightK crset
      where
        rightK rv = (,) <$> rightRRset dom typ DNS.classIN ttl rv <*> pure rank

valid :: Maybe (RRset, Ranking) -> Maybe (RRset, Ranking)
valid m = do
  (rrset, _rank) <- m
  guard $ rrsetValid rrset
  m

lookupValid :: Domain -> TYPE -> ContextT IO (Maybe (RRset, Ranking))
lookupValid dom typ = valid <$> lookupRRset "" dom typ

-- | when cache has EMPTY result, lookup SOA data for top domain of this zone
lookupRRsetEither :: String -> Domain -> TYPE -> ContextT IO (Maybe (Either (RRset, Ranking) RRset, Ranking))
lookupRRsetEither logMark dom typ = withLookupCache mkAlive logMark dom typ
  where
    mkAlive :: CacheHandler (Either (RRset, Ranking) RRset)
    mkAlive now dom_ typ_ cls cache = Cache.lookupAlive now (result now cache) dom_ typ_ cls cache
    result now cache ttl crs rank = case crs of
        Left srcDom -> do
            sp <- Cache.lookupAlive now (soaResult ttl srcDom) srcDom SOA DNS.classIN cache {- EMPTY hit. empty ranking and SOA result. -}
            Just (Left sp, rank)
        Right rv@(_rds, _msigs) -> do
            rrset <- rightRRset dom typ DNS.classIN ttl rv
            Just (Right rrset, rank)
    soaResult ettl srcDom ttl crs rank = either (const Nothing) rightK crs
      where
        rightK rv@(_rds, _msigs) = do
            rrset <- rightRRset srcDom SOA DNS.classIN (ettl `min` ttl {- treated as TTL of empty data -}) rv
            Just (rrset, rank)

rightRRset :: Domain -> TYPE -> CLASS -> TTL -> ([DNS.RData], Maybe [RD_RRSIG]) -> Maybe RRset
rightRRset dom typ cls ttl (rds, msigs)
    | null rds = Nothing
    | otherwise = case msigs of
        Nothing -> Just $ RRset dom typ cls ttl rds NotVerifiedRRS
        Just [] -> Nothing
        Just (sigs@(_:_)) -> Just $ RRset dom typ cls ttl rds (ValidRRS sigs)

---

lookupCache :: Domain -> TYPE -> ContextT IO (Maybe ([ResourceRecord], Ranking))
lookupCache = withLookupCache Cache.lookup ""

-- | when cache has EMPTY result, lookup SOA data for top domain of this zone
lookupCacheEither
    :: String
    -> Domain
    -> TYPE
    -> ContextT IO (Maybe (Either ([ResourceRecord], Ranking) [ResourceRecord], Ranking))
lookupCacheEither = withLookupCache Cache.lookupEither

cacheNoRRSIG :: [ResourceRecord] -> Ranking -> ContextT IO ()
cacheNoRRSIG rrs0 rank = do
    either crrsError insert $ SEC.canonicalRRsetSorted sortedRRs
  where
    prefix = ("cacheNoRRSIG: " ++)
    plogLn lv s = logLn lv $ prefix s
    crrsError _ =
        logLines Log.WARN $ prefix "no caching RR set:" : map (("\t" ++) . show) rrs0
    insert hrrs = do
        insertRRSet <- asks insert_
        hrrs $ \dom typ cls ttl rds -> do
            plogLn Log.DEBUG . unwords $ ["RRset:", show (((dom, typ, cls), ttl), rank), ' ' : show rds]
            liftIO $ insertRRSet (DNS.Question dom typ cls) ttl (Right (rds, Nothing)) rank
    (_, sortedRRs) = unzip $ SEC.sortRDataCanonical rrs0

cacheSection :: [ResourceRecord] -> Ranking -> ContextT IO ()
cacheSection rs rank = mapM_ (`cacheNoRRSIG` rank) $ rrsList rs
  where
    rrsKey rr = (rrname rr, rrtype rr, rrclass rr)
    rrsList = groupBy ((==) `on` rrsKey) . sortOn rrsKey

-- | The `cacheEmptySection zoneDom dom typ getRanked msg` caches two pieces of information from `msg`.
--   One is that the data for `dom` and `typ` are empty, and the other is the SOA record for the zone of
--   the sub-domains under `zoneDom`.
--   The `getRanked` function returns the section with the empty information.
{- FOURMOLU_DISABLE -}
cacheEmptySection
    :: Domain
    -> [RD_DNSKEY]
    -> Domain
    -> TYPE
    -> (DNSMessage -> ([ResourceRecord], Ranking))
    -> DNSMessage
    -> ContextT IO [RRset] {- returns verified authority section -}
{- FOURMOLU_ENABLE -}
cacheEmptySection zoneDom dnskeys dom typ getRanked msg = do
    Verify.withCanonical dnskeys rankedAuthority msg zoneDom SOA fromSOA nullSOA (pure []) $ \ps soaRRset cacheSOA -> do
        let doCache (soaDom, ncttl) = do
                cacheSOA
                withSection getRanked msg $ \_rrs rank -> cacheEmpty soaDom dom typ ncttl rank
        either (ncWarn >>> ($> [])) (doCache >>> ($> [soaRRset])) $ single ps
  where
    fromSOA :: ResourceRecord -> Maybe (Domain, TTL)
    fromSOA ResourceRecord{..} = (,) rrname . soaTTL <$> DNS.fromRData rdata
      where
        {- the minimum of the SOA.MINIMUM field and SOA's TTL
           https://datatracker.ietf.org/doc/html/rfc2308#section-3
           https://datatracker.ietf.org/doc/html/rfc2308#section-5 -}
        soaTTL soa = minimum [DNS.soa_minimum soa, rrttl, maxNCacheTTL]
        maxNCacheTTL = 21600
    nullSOA = ncWarn "no SOA records found" $> []

    single list = case list of
        [] -> Left "no SOA records found"
        [x] -> Right x
        _ : _ : _ -> Left "multiple SOA records found"
    ncWarn s
        | not $ null answer = do
            plogLines Log.DEBUG $ map ("\t" ++) ("because of non empty answers:" : map show answer)
        | otherwise = do
            plogLines Log.WARN $ map ("\t" ++) (("authority section:" :) . map show $ DNS.authority msg)
      where
        withDom = ["from-domain=" ++ show zoneDom ++ ",", "domain=" ++ show dom ++ ":", s]
        plogLines lv xs = logLines lv $ ("cacheEmptySection: " ++ unwords withDom) : xs
        answer = DNS.answer msg

cacheEmpty :: Domain -> Domain -> TYPE -> TTL -> Ranking -> ContextT IO ()
cacheEmpty zoneDom dom typ ttl rank = do
    logLn Log.DEBUG $ "cacheEmpty: " ++ show (zoneDom, dom, typ, ttl, rank)
    insertRRSet <- asks insert_
    liftIO $ insertSetEmpty zoneDom dom typ ttl rank insertRRSet

cacheAnswer :: Delegation -> Domain -> TYPE -> DNSMessage -> DNSQuery ([RRset], [RRset])
cacheAnswer Delegation{..} dom typ msg = do
    (ans, auth, cacheX) <- verify
    lift cacheX
    return (ans, auth)
  where
    verify = Verify.with dnskeys rankedAnswer msg dom typ Just nullX ncX $ \_ xRRset cacheX -> do
        let qinfo = show dom ++ " " ++ show typ
            (verifyMsg, verifyColor, raiseOnVerifyFailure)
                | FilledDS [] <- delegationDS = ("no verification - no DS, " ++ qinfo, Just Yellow, pure ())
                | rrsetValid xRRset = ("verification success - RRSIG of " ++ qinfo, Just Green, pure ())
                | NotFilledDS o <- delegationDS = ("not consumed not-filled DS: case=" ++ show o ++ ", " ++ qinfo, Nothing, pure ())
                | otherwise = ("verification failed - RRSIG of " ++ qinfo, Just Red, throwDnsError DNS.ServerFailure)
        lift $ clogLn Log.DEMO verifyColor verifyMsg
        raiseOnVerifyFailure
        pure ([xRRset], [], cacheX)
    nullX = lift $ doCacheEmpty <&> \e -> ([], e, pure ())
    doCacheEmpty = case rcode of
        {- authority sections for null answer -}
        DNS.NoErr -> cacheEmptySection zone dnskeys dom typ rankedAnswer msg
        DNS.NameErr -> cacheEmptySection zone dnskeys dom Cache.NX rankedAnswer msg
        _ -> return []
    ncX = pure ([], [], pure ())
    rcode = DNS.rcode $ DNS.flags $ DNS.header msg
    zone = delegationZone
    dnskeys = delegationDNSKEY

cacheNoDelegation :: Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> ContextT IO ()
cacheNoDelegation zoneDom dnskeys dom msg
    | rcode == DNS.NoErr = cacheNoDataNS $> ()
    | rcode == DNS.NameErr = nameErrors $> ()
    | otherwise = pure ()
  where
    nameErrors = Verify.withCanonical dnskeys rankedAnswer msg dom CNAME cnRD nullCNAME ncCNAME $
        \_rds _cnRRset cacheCNAME -> cacheCNAME *> cacheNoDataNS
    {- If you want to cache the NXDOMAIN of the CNAME destination, return it here.
       However, without querying the NS of the CNAME destination,
       you cannot obtain the record of rank that can be used for the reply. -}
    cnRD rr = DNS.fromRData $ rdata rr :: Maybe DNS.RD_CNAME
    nullCNAME = cacheEmptySection zoneDom dnskeys dom Cache.NX rankedAuthority msg
    ncCNAME = cacheNoDataNS
    cacheNoDataNS = cacheEmptySection zoneDom dnskeys dom NS rankedAuthority msg
    rcode = DNS.rcode $ DNS.flags $ DNS.header msg
