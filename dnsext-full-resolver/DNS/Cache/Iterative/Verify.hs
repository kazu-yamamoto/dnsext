{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Verify (
    withCanonical,
    withCanonical',
) where

-- GHC packages
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Reader (asks)
import DNS.Types.Decode (EpochTime)

-- other packages

-- dns packages
import DNS.Do53.Memo (Ranking)
import DNS.SEC (
    RD_DNSKEY,
    RD_RRSIG (..),
    TYPE,
    fromDNSTime,
    toDNSTime,
 )
import qualified DNS.SEC.Verify as SEC
import DNS.Types (
    CLASS,
    Domain,
    RData,
    ResourceRecord (..),
    TTL,
 )
import qualified DNS.Types as DNS
import qualified DNS.Types.Internal as DNS

-- this package
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Log as Log

withCanonical
    :: [RD_DNSKEY]
    -> (m -> ([ResourceRecord], Ranking))
    -> m
    -> Domain
    -> TYPE
    -> (ResourceRecord -> Maybe a)
    -> ContextT IO b
    -> ContextT IO b
    -> ([a] -> RRset -> ContextT IO () -> ContextT IO b)
    -> ContextT IO b
withCanonical dnskeys getRanked msg rrn rrty h nullK leftK rightK = do
    now <- liftIO =<< asks currentSeconds_
    let notCanonical rrs s = logLines Log.WARN (("not canonical RRset: " ++ s) : map (("\t" ++) . show) rrs) *> leftK
    withSection getRanked msg $ \srrs rank -> withCanonical' now dnskeys rrn rrty h srrs rank nullK notCanonical rightK

withCanonical'
    :: EpochTime
    -> [RD_DNSKEY]
    -> Domain
    -> TYPE
    -> (ResourceRecord -> Maybe a)
    -> [ResourceRecord]
    -> Ranking
    -> b
    -> ([ResourceRecord] -> String -> b)
    -> ([a] -> RRset -> ContextT IO () -> b)
    -> b
withCanonical' now dnskeys rrn rrty h srrs rank nullK leftK rightK0
    | null xRRs = nullK
    | otherwise = either (leftK xRRs) rightK $ canonicalRRset xRRs
  where
    (fromRDs, xRRs) = unzip [(x, rr) | rr <- srrs, rrtype rr == rrty, Just x <- [h rr], rrname rr == rrn]
    sigs = rrsigList rrn rrty srrs
    rightK p = withVerifiedRRset now dnskeys p sigs $ \rrset@(RRset dom typ cls minTTL rds sigrds) ->
        rightK0 fromRDs rrset (cacheRRset rank dom typ cls minTTL rds sigrds)

withVerifiedRRset
    :: EpochTime
    -> [RD_DNSKEY]
    -> (RRset, [DNS.SPut ()])
    -> [(RD_RRSIG, TTL)]
    -> (RRset -> a)
    -> a
withVerifiedRRset now dnskeys (RRset{..}, sortedRDatas) sigs vk =
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
        | null sigs = InvalidRRS {- dnskeys is not null, but sigs is null -}
        | null sigrds = InvalidRRS {- no good signature -}
        | otherwise = ValidRRS sigrds

{- get not verified canonical RRset -}
canonicalRRset :: [ResourceRecord] -> Either String (RRset, [DNS.SPut ()])
canonicalRRset rrs =
    either Left (Right . ($ rightK)) $ SEC.canonicalRRsetSorted sortedRRs
  where
    rightK dom typ cls ttl rds = (RRset dom typ cls ttl rds NotVerifiedRRS, sortedRDatas)
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
cacheRRset rank dom typ cls ttl rds _sigrds = do
    insertRRSet <- asks insert_
    logLn Log.DEBUG $ "cacheRRset: " ++ show (((dom, typ, cls), ttl), rank) ++ "  " ++ show rds
    liftIO $ insertRRSet (DNS.Question dom typ cls) ttl (Right rds) rank {- TODO: cache with RD_RRSIG -}
