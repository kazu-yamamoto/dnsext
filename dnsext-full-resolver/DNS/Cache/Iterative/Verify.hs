{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Verify (
    with,
    withCanonical,
    withCanonical',
) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Memo (Ranking)
import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import DNS.SEC
import qualified DNS.SEC.Verify as SEC
import DNS.Types
import qualified DNS.Types as DNS
import qualified DNS.Types.Internal as DNS
import System.Console.ANSI.Types

-- this package
import DNS.Cache.Imports
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils

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
    -> RRset -> [DNS.SPut ()] -> [(RD_RRSIG, TTL)]
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

{- get not verified canonical RRset -}
canonicalRRset :: [ResourceRecord] -> (String -> a) -> (RRset -> [DNS.SPut ()] -> a) -> a
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
