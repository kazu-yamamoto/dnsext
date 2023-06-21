{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Root ( refreshRoot, cachedDNSKEY, takeDEntryIPs ) where

-- GHC packages
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Reader (asks)
import Data.IORef (atomicWriteIORef, readIORef)
import Data.Maybe (fromMaybe)
import qualified Data.Set as Set

-- other packages

-- dns packages

import DNS.Do53.Memo (
    rankedAdditional,
    rankedAnswer,
 )
import DNS.SEC (
    RD_DNSKEY,
    RD_DS (..),
    RD_RRSIG (..),
    TYPE (DNSKEY),
 )
import qualified DNS.SEC.Verify as SEC
import DNS.Types (
    Domain,
    ResourceRecord (..),
    TTL,
    TYPE (NS),
 )
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))

-- this package
import DNS.Cache.Iterative.Cache
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Norec
import DNS.Cache.Iterative.Random
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import DNS.Cache.Iterative.Verify
import DNS.Cache.RootServers (rootServers)
import DNS.Cache.RootTrustAnchors (rootSepDS)
import DNS.Cache.Types (NE)
import qualified DNS.Log as Log

refreshRoot :: DNSQuery Delegation
refreshRoot = do
    curRef <- lift $ asks currentRoot_
    let refresh = do
            n <- getRoot
            liftIO $ atomicWriteIORef curRef $ Just n
            return n
        keep = do
            current <- liftIO $ readIORef curRef
            maybe refresh return current
        checkLife = do
            nsc <- lift $ lookupCache "." NS
            maybe refresh (const keep) nsc
    checkLife
  where
    getRoot = do
        let fallback s = lift $ do
                {- fallback to rootHint -}
                logLn Log.WARN $ "refreshRoot: " ++ s
                return rootHint
        either fallback return =<< rootPriming

{-
steps of root priming
1. get DNSKEY RRset of root-domain using `cachedDNSKEY` steps
2. query NS from root-domain with DO flag - get NS RRset and RRSIG
3. verify NS RRset of root-domain with RRSIGa
 -}
rootPriming :: DNSQuery (Either String Delegation)
rootPriming = do
    disableV6NS <- lift $ asks disableV6NS_
    ips <- selectIPs 4 $ takeDEntryIPs disableV6NS hintDes
    lift . logLn Log.DEMO . unwords $
        "root-server addresses for priming:" : [show ip | ip <- ips]
    ekeys <- cachedDNSKEY [rootSepDS] ips "."
    either (return . Left . emsg) (body ips) ekeys
  where
    emsg s = "rootPriming: " ++ s
    body ips dnskeys = do
        msgNS <- norec True ips "." NS

        (nsps, nsSet, cacheNS, nsGoodSigs) <- withSection rankedAnswer msgNS $ \rrs rank -> do
            let nsps = nsList "." (,) rrs
                (nss, nsRRs) = unzip nsps
                rrsigs = rrsigList "." NS rrs
            (RRset{..}, cacheNS) <- lift $ verifyAndCache dnskeys nsRRs rrsigs rank
            return (nsps, Set.fromList nss, cacheNS, rrsGoodSigs)

        (axRRs, cacheAX) <- withSection rankedAdditional msgNS $ \rrs rank -> do
            let axRRs = axList False (`Set.member` nsSet) (\_ x -> x) rrs
            return (axRRs, cacheSection axRRs rank)

        lift $ do
            cacheNS
            cacheAX
            case nsGoodSigs of
                [] -> do
                    logLn Log.WARN $ "rootPriming: DNSSEC verification failed"
                    case takeDelegationSrc nsps [] axRRs of
                        Nothing -> return $ Left $ emsg "no delegation"
                        Just d -> do
                            logLn Log.DEMO $
                                "root-priming: verification failed - RRSIG of NS: \".\"\n"
                                    ++ ppDelegation (delegationNS d)
                            return $ Right d
                _ : _ -> do
                    logLn Log.DEBUG $ "rootPriming: DNSSEC verification success"
                    case takeDelegationSrc nsps [rootSepDS] axRRs of
                        Nothing -> return $ Left $ emsg "no delegation"
                        Just (Delegation dom des dss _) -> do
                            logLn Log.DEMO $
                                "root-priming: verification success - RRSIG of NS: \".\"\n" ++ ppDelegation des
                            return $ Right $ Delegation dom des dss dnskeys

    Delegation _dot hintDes _ _ = rootHint

{-
steps to get verified and cached DNSKEY RRset
1. query DNSKEY from delegatee with DO flag - get DNSKEY RRset and its RRSIG
2. verify SEP DNSKEY of delegatee with DS
3. verify DNSKEY RRset of delegatee with RRSIG
4. cache DNSKEY RRset with RRSIG when validation passes
 -}
cachedDNSKEY
    :: [RD_DS] -> [IP] -> Domain -> DNSQuery (Either String [RD_DNSKEY])
cachedDNSKEY [] _ _ = return $ Left "cachedDSNKEY: no DS entry"
cachedDNSKEY dss aservers dom = do
    msg <- norec True aservers dom DNSKEY
    let rcode = DNS.rcode $ DNS.flags $ DNS.header msg
    case rcode of
        DNS.NoErr -> lift $ withSection rankedAnswer msg $ \rrs rank ->
            either (return . Left) (doCache rank) $ verifySEP dss dom rrs
        _ ->
            return $ Left $ "cachedDNSKEY: error rcode to get DNSKEY: " ++ show rcode
  where
    doCache rank (seps, dnskeys, rrsigs) = do
        (rrset, cacheDNSKEY) <-
            verifyAndCache (map fst seps) (map snd dnskeys) rrsigs rank
        if rrsetVerified rrset {- only cache DNSKEY RRset on verification successs -}
            then cacheDNSKEY *> return (Right $ map fst dnskeys)
            else return $ Left "cachedDNSKEY: no verified RRSIG found"

verifySEP
    :: [RD_DS]
    -> Domain
    -> [ResourceRecord]
    -> Either
        String
        ([(RD_DNSKEY, RD_DS)], [(RD_DNSKEY, ResourceRecord)], [(RD_RRSIG, TTL)])
verifySEP dss dom rrs = do
    let rrsigs = rrsigList dom DNSKEY rrs
    when (null rrsigs) $ Left $ verifyError "no RRSIG found for DNSKEY"

    let dnskeys = rrListWith DNSKEY DNS.fromRData dom (,) rrs
        seps =
            [ (key, ds)
            | (key, _) <- dnskeys
            , ds <- dss
            , Right () <- [SEC.verifyDS dom key ds]
            ]
    when (null seps) $ Left $ verifyError "no DNSKEY matches with DS"

    return (seps, dnskeys, rrsigs)
  where
    verifyError s = "verifySEP: " ++ s

-- {-# ANN rootHint ("HLint: ignore Use tuple-section") #-}
rootHint :: Delegation
rootHint =
    fromMaybe
        (error "rootHint: bad configuration.")
        $ takeDelegationSrc (nsList "." (,) ns) [] as
  where
    (ns, as) = rootServers

takeDEntryIPs :: Bool -> NE DEntry -> [IP]
takeDEntryIPs disableV6NS des = unique $ foldr takeDEntryIP [] (fst des : snd des)
  where
    unique = Set.toList . Set.fromList
    takeDEntryIP (DEonlyNS{}) xs = xs
    takeDEntryIP (DEwithAx _ ip@(IPv4{})) xs = ip : xs
    takeDEntryIP (DEwithAx _ ip@(IPv6{})) xs
        | disableV6NS = xs
        | otherwise = ip : xs
