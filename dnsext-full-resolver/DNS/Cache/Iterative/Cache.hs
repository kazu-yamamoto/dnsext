{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Cache (
    lookupCache,
    lookupCacheEither,
    cacheAnswer,
    cacheSection,
    cacheNoRRSIG,
    cacheNoDelegation,
) where

-- GHC packages
import Control.Arrow ((>>>))
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
    TYPE,
 )
import qualified DNS.SEC.Verify as SEC
import DNS.Types (
    DNSMessage,
    Domain,
    ResourceRecord (..),
    TTL,
    TYPE (CNAME, NS, SOA),
 )
import qualified DNS.Types as DNS

-- this package
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Cache.Iterative.Verify as Verify
import qualified DNS.Log as Log

lookupCache :: Domain -> TYPE -> ContextT IO (Maybe ([ResourceRecord], Ranking))
lookupCache dom typ = do
    getCache <- asks getCache_
    getSec <- asks currentSeconds_
    result <- liftIO $ do
        cache <- getCache
        ts <- getSec
        return $ Cache.lookup ts dom typ DNS.classIN cache
    let pprResult = maybe "miss" (\(_, rank) -> "hit: " ++ show rank) result
    logLn Log.DEBUG . unwords $ ["lookupCache:", show dom, show typ, show DNS.classIN, ":", pprResult]
    return result

-- | when cache has EMPTY result, lookup SOA data for top domain of this zone
lookupCacheEither
    :: String
    -> Domain
    -> TYPE
    -> ContextT IO (Maybe (Either ([ResourceRecord], Ranking) [ResourceRecord], Ranking))
lookupCacheEither logMark dom typ = do
    getCache <- asks getCache_
    getSec <- asks currentSeconds_
    result <- liftIO $ do
        cache <- getCache
        ts <- getSec
        return $ Cache.lookupEither ts dom typ DNS.classIN cache
    let plogLn lv s = logLn lv $ unwords ["lookupCacheEither:", logMark ++ ":", s]
        pprResult = maybe "miss" (\(_, rank) -> "hit: " ++ show rank) result
    plogLn Log.DEBUG . unwords $ [show dom, show typ, show DNS.classIN, ":", pprResult]
    return result

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
            liftIO $ insertRRSet (DNS.Question dom typ cls) ttl (Right rds) rank
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
    (ans, auth, cacheX, raiseOnVerifyFailure) <- lift verify
    raiseOnVerifyFailure
    lift cacheX
    return (ans, auth)
  where
    verify = Verify.withCanonical dnskeys rankedAnswer msg dom typ Just nullX ncX $ \_ xRRset cacheX -> do
        let qinfo = show dom ++ " " ++ show typ
            (verifyMsg, verifyColor, raiseOnVerifyFailure)
                | FilledDS [] <- delegationDS = ("no verification - no DS, " ++ qinfo, Just Yellow, pure ())
                | rrsetValid xRRset = ("verification success - RRSIG of " ++ qinfo, Just Green, pure ())
                | NotFilledDS o <- delegationDS = ("not consumed not-filled DS: case=" ++ show o ++ ", " ++ qinfo, Nothing, pure ())
                | otherwise = ("verification failed - RRSIG of " ++ qinfo, Just Red, throwDnsError DNS.ServerFailure)
        clogLn Log.DEMO verifyColor verifyMsg
        return ([xRRset], [], cacheX, raiseOnVerifyFailure)
    nullX = doCacheEmpty <&> \e -> ([], e, pure (), pure ())
    doCacheEmpty = case rcode of
        {- authority sections for null answer -}
        DNS.NoErr -> cacheEmptySection zone dnskeys dom typ rankedAnswer msg
        DNS.NameErr -> cacheEmptySection zone dnskeys dom Cache.NX rankedAnswer msg
        _ -> return []
    ncX = pure ([], [], pure (), pure ())
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
