{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
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

refreshRoot :: DNSQuery Delegation
refreshRoot = do
    curRef <- lift $ asks currentRoot_
    let refresh = do
            n <- getRoot
            liftIO $ atomicWriteIORef curRef $ Just n{delegationFresh = CachedD} {- got from IORef as cached -}
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
                asks rootHint_
        either fallback return =<< rootPriming

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
        putDelegation PPFull delegationNS (logLn Log.DEMO) (logLn Log.DEBUG . ("zone: \".\":\n" ++))
    nullNS = pure $ left "no NS RRs"
    ncNS _ncLog = pure $ left "not canonical NS RRs"
    pairNS rr = (,) <$> rdata rr `DNS.rdataField` DNS.ns_domain <*> pure rr

    verify getSec hint msgNS = Verify.cases getSec "." dnskeys rankedAnswer msgNS "." NS pairNS nullNS ncNS $
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
        hint <- lift $ asks rootHint_
        anchor <- lift $ asks rootAnchor_
        pure hint{delegationDS = anchor}
    priming hint = do
        getSec <- lift $ asks currentSeconds_
        ips <- delegationIPs hint
        msgNS <- norec True ips "." NS
        lift $ verify getSec hint msgNS
{- FOURMOLU_ENABLE -}

---

{- FOURMOLU_DISABLE -}
fillDelegationDNSKEY :: Delegation -> DNSQuery Delegation
fillDelegationDNSKEY d@Delegation{delegationDS = NotFilledDS o, delegationZone = zone} = do
    {- DS(Delegation Signer) is not filled -}
    lift $ logLn Log.WARN $ "fillDelegationDNSKEY: not consumed not-filled DS: case=" ++ show o ++ " zone: " ++ show zone
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
    maybe (list1 nullIPs query =<< delegationIPs d) (lift . fill . toDNSKEYs) =<< lift (lookupValid zone DNSKEY)
  where
    zone = delegationZone
    toDNSKEYs (rrset, _rank) = [rd | rd0 <- rrsRDatas rrset, Just rd <- [DNS.fromRData rd0]]
    fill dnskeys = pure d{delegationDNSKEY = dnskeys}
    nullIPs = lift $ logLn Log.WARN "fillDelegationDNSKEY: ip list is null" *> pure d
    verifyFailed ~es = lift (logLn Log.WARN $ "fillDelegationDNSKEY: " ++ es) *> pure d
    query ips = do
        lift $ logLn Log.DEMO . unwords $ ["fillDelegationDNSKEY: query", show (zone, DNSKEY), "servers:"] ++ [show ip | ip <- ips]
        either verifyFailed (lift . fill) =<< cachedDNSKEY getSEP ips zone
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- Get authoritative server addresses from the delegation information.
delegationIPs :: Delegation -> DNSQuery [Address]
delegationIPs Delegation{..} = do
    disableV6NS <- lift (asks disableV6NS_)
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
cachedDNSKEY :: ([ResourceRecord] -> Either String (NonEmpty RD_DNSKEY)) -> [Address] -> Domain -> DNSQuery (Either String [RD_DNSKEY])
cachedDNSKEY getSEPs aservers zone = do
    msg <- norec True aservers zone DNSKEY
    let rcode = DNS.rcode msg
    case rcode of
        DNS.NoErr -> withSection rankedAnswer msg $ \srrs _rank ->
            either (pure . Left) (verifyDNSKEY msg) $ getSEPs srrs
        _ -> pure $ Left $ "cachedDNSKEY: error rcode to get DNSKEY: " ++ show rcode
  where
    cachedResult krds dnskeyRRset cacheDNSKEY
        | rrsetValid dnskeyRRset = lift cacheDNSKEY $> Right krds {- only cache DNSKEY RRset on verification successs -}
        | otherwise = pure $ Left $ "cachedDNSKEY: no verified RRSIG found: " ++ show (rrsMayVerified dnskeyRRset)
    verifyDNSKEY msg (s:|ss) = do
        let dnskeyRD rr = DNS.fromRData $ rdata rr :: Maybe RD_DNSKEY
            nullDNSKEY = pure $ Left "cachedDNSKEY: null DNSKEYs" {- no DNSKEY case -}
            ncDNSKEY _ncLog = pure $ Left "cachedDNSKEY: not canonical"
        getSec <- lift $ asks currentSeconds_
        Verify.cases getSec zone (s:ss) rankedAnswer msg zone DNSKEY dnskeyRD nullDNSKEY ncDNSKEY cachedResult

norec :: Bool -> [Address] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnssecOK aservers name typ = ExceptT $ do
    e <- Norec.norec' dnssecOK aservers name typ
    either left (pure . handleResponseError Left Right) e
  where
    left e = cacheDNSError name typ Cache.RankAnswer e $> dnsError e
    dnsError e = Left $ uncurry DnsError $ unwrapDNSErrorInfo e
