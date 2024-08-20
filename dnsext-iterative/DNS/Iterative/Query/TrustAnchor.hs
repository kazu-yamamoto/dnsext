{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.TrustAnchor (
    fillDelegationDNSKEY,
    delegationIPs,
    --
    norec,
    --
    refreshRoot,
    rootPriming,
) where

-- GHC packages
import Data.IORef (atomicWriteIORef, readIORef)
import qualified Data.List.NonEmpty as NE
import qualified Data.Set as Set

-- other packages

-- dnsext packages
import qualified DNS.Log as Log
import DNS.RRCache (
    rankedAdditional,
    rankedAnswer,
 )
import qualified DNS.RRCache as Cache
import DNS.SEC
import DNS.Types
import qualified DNS.Types as DNS
import System.Console.ANSI.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Helpers
import qualified DNS.Iterative.Query.Norec as Norec
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
import qualified DNS.Iterative.Query.Verify as Verify

{- FOURMOLU_DISABLE -}
refreshRoot :: DNSQuery Delegation
refreshRoot = do
    curRef <- asks currentRoot_
    let refresh = do
            n <- getRoot
            liftIO $ atomicWriteIORef curRef $ Just n{delegationFresh = CachedD} {- got from IORef as cached -}
            return n
        keep = do
            current <- liftIO $ readIORef curRef
            maybe refresh return current
        checkLife = do
            nsc <- lookupRR "." NS
            maybe refresh (const keep) nsc
    checkLife
  where
    getRoot = do
        let fallback s = do
                {- fallback to rootHint -}
                logLn Log.WARN $ "refreshRoot: " ++ s
                asks rootHint_
        either fallback return =<< rootPriming
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
{-
steps of root priming
1. get DNSKEY RRset of root-domain using `fillDelegationDNSKEY` steps
2. query NS from root-domain with DO flag - get NS RRset and RRSIG
3. verify NS RRset of root-domain with RRSIGa
 -}
rootPriming :: DNSQuery (Either String Delegation)
rootPriming =
    priming =<< fillDelegationDNSKEY =<< getHint
  where
    left s = Left $ "root-priming: " ++ s
    logResult delegationNS color s = do
        clogLn Log.DEMO (Just color) $ "root-priming: " ++ s
        short <- asks shortLog_
        logLn Log.DEMO $ ppDelegation short delegationNS
    nullNS = pure $ left "no NS RRs"
    ncNS _ncLog = pure $ left "not canonical NS RRs"
    pairNS rr = (,) <$> rdata rr `DNS.rdataField` DNS.ns_domain <*> pure rr

    verify hint msgNS = Verify.cases NoCheckDisabled "." dnskeys rankedAnswer msgNS "." NS pairNS nullNS ncNS $
        \nsps nsRRset postAction -> do
            let nsSet = Set.fromList $ map fst nsps
                (axRRs, cacheAX) = withSection rankedAdditional msgNS $ \rrs rank ->
                    (axList False (`Set.member` nsSet) (\_ rr -> rr) rrs, cacheSection axRRs rank)
                result "."  ents
                    | not $ rrsetValid nsRRset = do
                          postAction  {- Call action for logging error info. `Verify.cacheRRset` does not cache invalids -}
                          logResult ents Red "verification failed - RRSIG of NS: \".\"" $> left "DNSSEC verification failed"
                    | otherwise                = do
                          postAction *> cacheAX
                          logResult ents Green "verification success - RRSIG of NS: \".\""
                          pure $ Right $ hint{delegationNS = ents, delegationFresh = FreshD}
                result apex _ents = pure $ left $ "inconsistent zone apex: " ++ show apex ++ ", not \".\""
            fromMaybe (pure $ left "no delegation") $ findDelegation' result nsps axRRs
      where
        dnskeys = delegationDNSKEY hint

    getHint = do
        hint <- asks rootHint_
        anchor <- asks rootAnchor_
        pure hint{delegationDS = anchor}
    priming hint = do
        sas <- delegationIPs hint
        let zone = "."
        let short = False
        logLn Log.DEMO $ unwords (["root-priming: query", show zone, show NS] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]])
        msgNS <- norec True sas zone NS
        verify hint msgNS
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY :: Delegation -> DNSQuery Delegation
fillDelegationDNSKEY d@Delegation{delegationDS = NotFilledDS o, delegationZone = zone} = do
    {- DS(Delegation Signer) is not filled -}
    logLn Log.WARN $ "require-dnskey: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show zone
    pure d
fillDelegationDNSKEY d@Delegation{delegationDS = FilledDS []} = pure d {- DS(Delegation Signer) does not exist -}
fillDelegationDNSKEY d@Delegation{..} = fillDelegationDNSKEY' getSEP d
  where
    zone = delegationZone
    getSEP = case delegationDS of
        AnchorSEP _ sep     -> \_ -> Right sep
        FilledDS dss@(_:_)  -> (fmap fst <$>) . Verify.sepDNSKEY dss zone . rrListWith DNSKEY DNS.fromRData zone const
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY' :: ([ResourceRecord] -> Either String (NonEmpty RD_DNSKEY)) -> Delegation -> DNSQuery Delegation
fillDelegationDNSKEY' _      d@Delegation{delegationDNSKEY = _:_}     = pure d
fillDelegationDNSKEY' getSEP d@Delegation{delegationDNSKEY = [] , ..} =
    maybe (list1 nullIPs query =<< delegationIPs d) (fill . toDNSKEYs) =<< lookupValidRR "require-dnskey" zone DNSKEY
  where
    zone = delegationZone
    toDNSKEYs (rrs, _rank) = [rd | rr <- rrs, Just rd <- [DNS.fromRData $ rdata rr]]
    fill dnskeys = pure d{delegationDNSKEY = dnskeys}
    nullIPs = logLn Log.WARN "require-dnskey: address list is null" $> d
    verifyFailed ~es = logLn Log.WARN ("require-dnskey: " ++ es) $> d
    query sas = either verifyFailed fill =<< cachedDNSKEY getSEP sas zone
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- Get authoritative server addresses from the delegation information.
delegationIPs :: Delegation -> DNSQuery [Address]
delegationIPs Delegation{..} = do
    disableV6NS <- asks disableV6NS_
    ips <- dentryToRandomIP entryNum addrNum disableV6NS dentry
    when (null ips) $ throwDnsError DNS.UnknownDNSError  {- assume filled IPs by fillDelegation -}
    pure ips
  where
    dentry = NE.toList delegationNS
    entryNum = 2
    addrNum = 2
{- FOURMOLU_ENABLE -}

{-
steps to get verified and cached DNSKEY RRset
1. query DNSKEY from delegatee with DO flag - get DNSKEY RRset and its RRSIG
2. verify SEP DNSKEY of delegatee with DS
3. verify DNSKEY RRset of delegatee with RRSIG
4. cache DNSKEY RRset with RRSIG when validation passes
 -}
cachedDNSKEY
    :: ([ResourceRecord] -> Either String (NonEmpty RD_DNSKEY)) -> [Address] -> Domain -> DNSQuery (Either String [RD_DNSKEY])
cachedDNSKEY getSEPs sas zone = do
    short <- asks shortLog_
    logLn Log.DEMO $ unwords (["require-dnskey: query", show zone, show DNSKEY] ++ [w | short, w <- "to" : [pprAddr sa | sa <- sas]])
    msg <- norec True sas zone DNSKEY
    let rcode = DNS.rcode msg
    case rcode of
        DNS.NoErr -> withSection rankedAnswer msg $ \srrs _rank ->
            either (pure . Left) (verifyDNSKEY msg) $ getSEPs srrs
        _ -> pure $ Left $ "cachedDNSKEY: error rcode to get DNSKEY: " ++ show rcode
  where
    cachedResult krds dnskeyRRset cacheDNSKEY
        | rrsetValid dnskeyRRset = cacheDNSKEY $> Right krds {- only cache DNSKEY RRset on verification successs -}
        | otherwise = pure $ Left $ "cachedDNSKEY: no verified RRSIG found: " ++ show (rrsMayVerified dnskeyRRset)
    verifyDNSKEY msg (s :| ss) = do
        let dnskeyRD rr = DNS.fromRData $ rdata rr :: Maybe RD_DNSKEY
            {- no DNSKEY case -}
            nullDNSKEY = cacheSectionNegative zone [] zone DNSKEY rankedAnswer msg [] $> Left "cachedDNSKEY: null DNSKEYs"
            ncDNSKEY _ncLog = pure $ Left "cachedDNSKEY: not canonical"
        Verify.cases NoCheckDisabled zone (s : ss) rankedAnswer msg zone DNSKEY dnskeyRD nullDNSKEY ncDNSKEY cachedResult

norec :: Bool -> [Address] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnssecOK aservers name typ = ExceptT $ do
    e <- Norec.norec' dnssecOK aservers name typ
    either left (pure . handleResponseError Left Right) e
  where
    left e = cacheDNSError name typ Cache.RankAnswer e $> dnsError e
    dnsError e = Left $ uncurry DnsError $ unwrapDNSErrorInfo e
