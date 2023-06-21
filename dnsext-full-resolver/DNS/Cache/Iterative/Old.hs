{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Old where

-- GHC packages
import qualified Control.Exception as E
import Control.Monad (join, when)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT (..), runExceptT, throwE)
import Control.Monad.Trans.Reader (ReaderT (..), asks)
import Data.Function (on)
import Data.Functor (($>))
import Data.IORef (atomicWriteIORef, readIORef)
import Data.List (groupBy, sort, uncons)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Set as Set

-- other packages

import System.Console.ANSI.Types

-- dns packages

import DNS.Do53.Client (
    EdnsControls (..),
    FlagOp (..),
    HeaderControls (..),
    QueryControls (..),
    defaultResolvActions,
    ractionGenId,
    ractionGetTime,
    ractionLog,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    ResolvEnv (..),
    ResolvInfo (..),
    defaultResolvInfo,
    udpTcpResolver,
 )
import qualified DNS.Do53.Internal as DNS
import DNS.Do53.Memo (
    Ranking (RankAdditional),
    rankedAdditional,
    rankedAnswer,
    rankedAuthority,
 )
import qualified DNS.Do53.Memo as Cache
import DNS.SEC (
    RD_DNSKEY,
    RD_DS (..),
    RD_RRSIG (..),
    TYPE (DNSKEY, DS, NSEC, NSEC3, RRSIG),
 )
import qualified DNS.SEC.Verify as SEC
import DNS.Types (
    DNSHeader,
    DNSMessage,
    Domain,
    EDNSheader,
    Question (..),
    RData,
    ResourceRecord (..),
    TTL,
    TYPE (A, AAAA, CNAME, NS, SOA),
    classIN,
 )
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))

-- this package
import DNS.Cache.Iterative.Cache
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.Random
import DNS.Cache.Iterative.Rev
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import DNS.Cache.Iterative.Verify
import DNS.Cache.RootServers (rootServers)
import DNS.Cache.RootTrustAnchors (rootSepDS)
import DNS.Cache.Types (NE)
import qualified DNS.Log as Log

-- $setup
-- >>> :set -XOverloadedStrings

-----

{- datatypes to propagate request flags -}

data RequestDO
    = DnssecOK
    | NoDnssecOK
    deriving (Show)

data RequestCD
    = CheckDisabled
    | NoCheckDisabled
    deriving (Show)

data RequestAD
    = AuthenticatedData
    | NoAuthenticatedData
    deriving (Show)

{- request flags to pass iterative query.
  * DO (DNSSEC OK) must be 1 for DNSSEC available resolver
    * https://datatracker.ietf.org/doc/html/rfc4035#section-3.2.1
  * CD (Checking Disabled)
  * AD (Authenticated Data)
    * https://datatracker.ietf.org/doc/html/rfc6840#section-5.7
      "setting the AD bit in a query as a signal indicating that the requester understands and is interested in the value of the AD bit in the response" -}
requestDO :: QueryControls -> RequestDO
requestDO ic = case extDO $ qctlEdns ic of
    FlagSet -> DnssecOK
    _ -> NoDnssecOK

_requestCD :: QueryControls -> RequestCD
_requestCD ic = case cdBit $ qctlHeader ic of
    FlagSet -> CheckDisabled
    _ -> NoCheckDisabled

_requestAD :: QueryControls -> RequestAD
_requestAD ic = case adBit $ qctlHeader ic of
    FlagSet -> AuthenticatedData
    _ -> NoAuthenticatedData

---

{-
反復検索の概要

目的のドメインに対して、TLD(トップレベルドメイン) から子ドメインの方向へと順に、権威サーバへの A クエリを繰り返す.
権威サーバへの A クエリの返答メッセージには、
authority セクションに、次の権威サーバ群の名前 (NS) が、
additional セクションにその名前に対するアドレス (A および AAAA) が入っている.
この情報を使って、繰り返し、子ドメインへの検索を行なう.
検索ドメインの初期値はTLD、権威サーバ群の初期値はルートサーバとなる.
 -}

dnsQueryT
    :: (Env -> QueryControls -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT k = ExceptT $ ReaderT $ ReaderT . k

runDNSQuery
    :: DNSQuery a -> Env -> QueryControls -> IO (Either QueryError a)
runDNSQuery q = runReaderT . runReaderT (runExceptT q)

handleResponseError :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError e f msg
    | DNS.qOrR flags /= DNS.QR_Response = e $ NotResponse (DNS.qOrR flags) msg
    | DNS.ednsHeader msg == DNS.InvalidEDNS =
        e $ InvalidEDNS (DNS.ednsHeader msg) msg
    | DNS.rcode flags
        `notElem` [DNS.NoErr, DNS.NameErr] =
        e $ HasError (DNS.rcode flags) msg
    | otherwise = f msg
  where
    flags = DNS.flags $ DNS.header msg

-- responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- responseErrDNSQuery = handleResponseError throwE return  :: DNSMessage -> DNSQuery DNSMessage

-- 返答メッセージを作る
getReplyMessage
    :: Env
    -> DNSMessage
    -> IO (Either String DNSMessage)
getReplyMessage cxt reqM = case uncons $ DNS.question reqM of
    Nothing -> return $ Left "empty question"
    Just qs@(DNS.Question bn typ _, _) -> do
        let reqH = DNS.header reqM
            reqEH = DNS.ednsHeader reqM
            getResult = do
                guardRequestHeader reqH reqEH
                replyResult bn typ
        (\ers -> replyMessage ers (DNS.identifier reqH) $ uncurry (:) qs)
            <$> runDNSQuery getResult cxt (ctrlFromRequestHeader reqH reqEH)

-- キャッシュから返答メッセージを作る
-- Nothing のときキャッシュ無し
-- Just Left はエラー
getReplyCached
    :: Env
    -> DNSMessage
    -> IO (Maybe (Either String DNSMessage))
getReplyCached cxt reqM = case uncons $ DNS.question reqM of
    Nothing -> return $ Just $ Left "empty question"
    Just qs@(DNS.Question bn typ _, _) -> do
        let reqH = DNS.header reqM
            reqEH = DNS.ednsHeader reqM
            getResult = do
                guardRequestHeader reqH reqEH
                replyResultCached bn typ
            mkReply ers = replyMessage ers (DNS.identifier reqH) (uncurry (:) qs)
        fmap mkReply . either (Just . Left) (Right <$>)
            <$> runDNSQuery getResult cxt (ctrlFromRequestHeader reqH reqEH)

-- 最終的な解決結果を得る
runResolve
    :: Env
    -> Domain
    -> TYPE
    -> QueryControls
    -> IO
        ( Either
            QueryError
            (([RRset], Domain), Either Result (DNSMessage, ([RRset], [RRset])))
        )
runResolve cxt n typ cd = runDNSQuery (resolve n typ) cxt cd

-- 権威サーバーからの解決結果を得る
runResolveJust
    :: Env
    -> Domain
    -> TYPE
    -> QueryControls
    -> IO (Either QueryError (DNSMessage, Delegation))
runResolveJust cxt n typ cd = runDNSQuery (resolveJust n typ) cxt cd

-- 反復後の委任情報を得る
runIterative
    :: Env
    -> Delegation
    -> Domain
    -> QueryControls
    -> IO (Either QueryError Delegation)
runIterative cxt sa n cd = runDNSQuery (iterative sa n) cxt cd

-----

ctrlFromRequestHeader :: DNSHeader -> EDNSheader -> QueryControls
ctrlFromRequestHeader reqH reqEH = DNS.doFlag doOp <> DNS.cdFlag cdOp <> DNS.adFlag adOp
  where
    doOp
        | dnssecOK = FlagSet
        | otherwise = FlagClear
    cdOp
        | dnssecOK, DNS.chkDisable flags = FlagSet {- only check when DNSSEC OK -}
        | otherwise = FlagClear
    adOp
        | dnssecOK, DNS.authenData flags = FlagSet {- only check when DNSSEC OK -}
        | otherwise = FlagClear

    flags = DNS.flags reqH
    dnssecOK = case reqEH of
        DNS.EDNSheader edns | DNS.ednsDnssecOk edns -> True
        _ -> False

guardRequestHeader :: DNSHeader -> EDNSheader -> DNSQuery ()
guardRequestHeader reqH reqEH
    | reqEH == DNS.InvalidEDNS =
        throwE $ InvalidEDNS DNS.InvalidEDNS DNS.defaultResponse
    | not rd = throwE $ HasError DNS.Refused DNS.defaultResponse
    | otherwise = pure ()
  where
    rd = DNS.recDesired $ DNS.flags reqH

replyMessage
    :: Either QueryError Result
    -> DNS.Identifier
    -> [DNS.Question]
    -> Either String DNSMessage
replyMessage eas ident rqs =
    either queryError (Right . message) eas
  where
    dnsError de = fmap message $ (,,) <$> rcodeDNSError de <*> pure [] <*> pure []
    rcodeDNSError e = case e of
        DNS.RetryLimitExceeded -> Right DNS.ServFail
        DNS.FormatError -> Right DNS.FormatErr
        DNS.ServerFailure -> Right DNS.ServFail
        DNS.NotImplemented -> Right DNS.NotImpl
        DNS.OperationRefused -> Right DNS.ServFail {- like bind9 behavior -}
        DNS.BadOptRecord -> Right DNS.BadVers
        _ -> Left $ "DNSError: " ++ show e

    queryError qe = case qe of
        DnsError e -> dnsError e
        NotResponse{} -> Left "qORr is not response"
        InvalidEDNS{} -> Left "Invalid EDNS"
        HasError rc _m -> Right $ message (rrc, [], [])
          where
            rrc = case rc of
                DNS.Refused -> DNS.ServFail
                _ -> rc

    message (rcode, rrs, auth) =
        res
            { DNS.header =
                h
                    { DNS.identifier = ident
                    , DNS.flags = f{DNS.authAnswer = False, DNS.rcode = rcode}
                    }
            , DNS.answer = rrs
            , DNS.authority = auth
            , DNS.question = rqs
            }
    res = DNS.defaultResponse
    h = DNS.header res
    f = DNS.flags h

-- 反復検索を使って返答メッセージ用の結果コードと応答セクションを得る.
replyResult :: Domain -> TYPE -> DNSQuery Result
replyResult n typ = do
    ((cnrrs, _rn), etm) <- resolve n typ
    reqDO <- lift . lift $ asks requestDO
    let fromRRsets = concatMap $ rrListFromRRset reqDO
        fromMessage (msg, (vans, vauth)) = (DNS.rcode $ DNS.flags $ DNS.header msg, fromRRsets vans, fromRRsets vauth)
    return $ makeResult reqDO cnrrs $ either id fromMessage etm

replyResultCached :: Domain -> TYPE -> DNSQuery (Maybe Result)
replyResultCached n typ = do
    ((cnrrs, _rn), e) <- resolveByCache n typ
    reqDO <- lift . lift $ asks requestDO
    return $ either (Just . makeResult reqDO cnrrs) (const Nothing) e

makeResult :: RequestDO -> [RRset] -> Result -> Result
makeResult reqDO cnRRset (rcode, ans, auth) =
    ( rcode
    , denyAnswer reqDO $ concat $ map (rrListFromRRset reqDO) cnRRset ++ [ans]
    , allowAuthority reqDO auth
    )
  where
    denyAnswer DnssecOK rrs = rrs
    denyAnswer NoDnssecOK rrs = foldr takeNODNSSEC [] rrs
      where
        takeNODNSSEC rr@ResourceRecord{..} xs
            | rrtype `elem` dnssecTypes = xs
            | otherwise = rr : xs

    allowAuthority NoDnssecOK = foldr takeSOA []
      where
        takeSOA rr@ResourceRecord{rrtype = SOA} xs = rr : xs
        takeSOA _ xs = xs
    allowAuthority DnssecOK = foldr takeAuth []
      where
        allowTypes = SOA : dnssecTypes
        takeAuth rr@ResourceRecord{..} xs
            | rrtype `elem` allowTypes = rr : xs
            | otherwise = xs

    dnssecTypes = [DNSKEY, DS, RRSIG, NSEC, NSEC3]

maxCNameChain :: Int
maxCNameChain = 16

resolveByCache
    :: Domain
    -> TYPE
    -> DNSQuery (([RRset], Domain), Either Result ((), ([RRset], [RRset])))
resolveByCache =
    resolveLogic
        "cache"
        (\_ -> pure ((), ([], [])))
        (\_ _ -> pure ((), Nothing, ([], [])))

{- 反復検索を使って最終的な権威サーバーからの DNSMessage を得る.
   目的の TYPE の RankAnswer 以上のキャッシュ読み出しが得られた場合はそれが結果となる.
   目的の TYPE が CNAME 以外の場合、結果が CNAME なら繰り返し解決する. その際に CNAME レコードのキャッシュ書き込みを行なう.
   目的の TYPE の結果レコードをキャッシュする. -}
resolve
    :: Domain
    -> TYPE
    -> DNSQuery (([RRset], Domain), Either Result (DNSMessage, ([RRset], [RRset])))
resolve = resolveLogic "query" resolveCNAME resolveTYPE

resolveLogic
    :: String
    -> (Domain -> DNSQuery (a, ([RRset], [RRset])))
    -> (Domain -> TYPE -> DNSQuery (a, Maybe (Domain, RRset), ([RRset], [RRset])))
    -> Domain
    -> TYPE
    -> DNSQuery (([RRset], Domain), Either Result (a, ([RRset], [RRset])))
resolveLogic logMark cnameHandler typeHandler n0 typ =
    maybe notSpecial special $ takeSpecialRevDomainResult n0
  where
    special result = return (([], n0), Left result)
    notSpecial
        | typ == Cache.NX = called *> return (([], n0), Left (DNS.NoErr, [], []))
        | typ == CNAME = called *> justCNAME n0
        | otherwise = called *> recCNAMEs 0 n0 id
    called = lift $ logLn Log.DEBUG $ "resolve: " ++ logMark ++ ": " ++ show (n0, typ)
    justCNAME bn = do
        let noCache = do
                result <- cnameHandler bn
                pure (([], bn), Right result)

            withNXC (soa, _rank) = pure (([], bn), Left (DNS.NameErr, [], soa))

            cachedCNAME (rrs, soa) =
                pure
                    ( ([], bn)
                    , Left
                        ( DNS.NoErr
                        , rrs
                        , soa {- target RR is not CNAME destination but CNAME, so NoErr -}
                        )
                    )

        maybe
            (maybe noCache withNXC =<< lift (lookupNX bn))
            (cachedCNAME . either (\soa -> ([], soa)) (\(_cn, cnRR) -> ([cnRR], [])))
            =<< lift (lookupCNAME bn)

    -- CNAME 以外のタイプの検索について、CNAME のラベルで検索しなおす.
    -- recCNAMEs :: Int -> Domain -> [RRset] -> DNSQuery (([RRset], Domain), Either Result a)
    recCNAMEs cc bn dcnRRsets
        | cc > mcc =
            lift
                (logLn Log.WARN $ "query: cname chain limit exceeded: " ++ show (n0, typ))
                *> throwDnsError DNS.ServerFailure
        | otherwise = do
            let recCNAMEs_ (cn, cnRRset) = recCNAMEs (succ cc) cn (dcnRRsets . (cnRRset :))
                noCache = do
                    (msg, cname, vsec) <- typeHandler bn typ
                    maybe (pure ((dcnRRsets [], bn), Right (msg, vsec))) recCNAMEs_ cname

                withNXC (soa, _rank) = pure ((dcnRRsets [], bn), Left (DNS.NameErr, [], soa))

                noTypeCache =
                    maybe
                        (maybe noCache withNXC =<< lift (lookupNX bn))
                        recCNAMEs_ {- recurse with cname cache -}
                        =<< lift ((recover =<<) . joinE <$> lookupCNAME bn)
                  where
                    {- when CNAME has NODATA, do not loop with CNAME domain -}
                    joinE = (either (const Nothing) Just =<<)
                    recover (dom, cnrr) = (,) dom <$> recoverRRset [cnrr]

                cachedType (tyRRs, soa) = pure ((dcnRRsets [], bn), Left (DNS.NoErr, tyRRs, soa))

            maybe
                noTypeCache
                ( cachedType
                    . either
                        (\(soa, _rank) -> ([], soa))
                        (\tyRRs -> (tyRRs, [] {- return cached result with target typ -}))
                )
                =<< lift (lookupType bn typ)
      where
        mcc = maxCNameChain

    lookupNX :: Domain -> ContextT IO (Maybe ([ResourceRecord], Ranking))
    lookupNX bn =
        maybe (return Nothing) (either (return . Just) inconsistent)
            =<< lookupType bn Cache.NX
      where
        inconsistent rrs = do
            logLn Log.WARN $
                "resolve: inconsistent NX cache found: dom=" ++ show bn ++ ", " ++ show rrs
            return Nothing

    -- Nothing のときはキャッシュに無し
    -- Just Left のときはキャッシュに有るが CNAME レコード無し
    lookupCNAME
        :: Domain -> ContextT IO (Maybe (Either [ResourceRecord] (Domain, ResourceRecord)))
    lookupCNAME bn = do
        maySOAorCNRRs <- lookupType bn CNAME {- TODO: get CNAME RRSIG from cache -}
        return $ do
            let soa (rrs, _rank) = Just $ Left rrs
                cname rrs = Right . fst <$> uncons (cnameList bn (,) rrs)
            {- should not be possible, but as cache miss-hit when empty CNAME list case -}
            either soa cname =<< maySOAorCNRRs

    lookupType bn t = (replyRank =<<) <$> lookupCacheEither logMark bn t
    replyRank (x, rank)
        -- 最も低い ranking は reply の answer に利用しない
        -- https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1
        | rank <= RankAdditional = Nothing
        | otherwise = Just x

{- CNAME のレコードを取得し、キャッシュする -}
resolveCNAME :: Domain -> DNSQuery (DNSMessage, ([RRset], [RRset]))
resolveCNAME bn = do
    (msg, d) <- resolveJust bn CNAME
    (,) msg <$> cacheAnswer d bn CNAME msg

{- 目的の TYPE のレコードの取得を試み、結果の DNSMessage を返す.
   結果が CNAME なら、その RR も返す.
   どちらの場合も、結果のレコードをキャッシュする. -}
resolveTYPE
    :: Domain
    -> TYPE
    -> DNSQuery
        ( DNSMessage
        , Maybe (Domain, RRset)
        , ([RRset], [RRset])
        ) {- result msg, cname, verified answer, verified authority -}
resolveTYPE bn typ = do
    (msg, delegation@Delegation{..}) <- resolveJust bn typ
    let checkTypeRR =
            when (any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg) $
                throwDnsError DNS.UnexpectedRDATA -- CNAME と目的の TYPE が同時に存在した場合はエラー
    withSection rankedAnswer msg $ \rrs rank -> do
        let (cnames, cnameRRs) = unzip $ cnameList bn (,) rrs
            noCNAME = do
                (,,) msg Nothing <$> cacheAnswer delegation bn typ msg
            withCNAME cn = do
                (cnameRRset, cacheCNAME) <-
                    verifyAndCache delegationDNSKEY cnameRRs (rrsigList bn CNAME rrs) rank
                cacheCNAME
                return (msg, Just (cn, cnameRRset), ([], []))
        case cnames of
            [] -> noCNAME
            cn : _ -> checkTypeRR *> lift (withCNAME cn)

maxNotSublevelDelegation :: Int
maxNotSublevelDelegation = 16

-- 反復検索を使って最終的な権威サーバーからの DNSMessage とその委任情報を得る. CNAME は解決しない.
resolveJust :: Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJust = resolveJustDC 0

resolveJustDC :: Int -> Domain -> TYPE -> DNSQuery (DNSMessage, Delegation)
resolveJustDC dc n typ
    | dc > mdc = do
        lift . logLn Log.WARN $
            "resolve-just: not sub-level delegation limit exceeded: " ++ show (n, typ)
        throwDnsError DNS.ServerFailure
    | otherwise = do
        lift . logLn Log.DEMO $
            "resolve-just: " ++ "dc=" ++ show dc ++ ", " ++ show (n, typ)
        root <- refreshRoot
        nss@Delegation{..} <- iterative_ dc root $ reverse $ DNS.superDomains n
        sas <- delegationIPs dc nss
        lift . logLn Log.DEMO . unwords $
            ["resolve-just: query", show (n, typ), "selected addresses:"]
                ++ [show sa | sa <- sas]
        let dnssecOK = not (null delegationDS) && not (null delegationDNSKEY)
        (,) <$> norec dnssecOK sas n typ <*> pure nss
  where
    mdc = maxNotSublevelDelegation

nsDomain :: DEntry -> Domain
nsDomain (DEwithAx dom _) = dom
nsDomain (DEonlyNS dom) = dom

v4DEntryList :: [DEntry] -> [DEntry]
v4DEntryList [] = []
v4DEntryList des@(de : _) = concatMap skipAAAA $ byNS des
  where
    byNS = groupBy ((==) `on` nsDomain)
    skipAAAA = nullCase . filter (not . aaaaDE)
      where
        aaaaDE (DEwithAx _ (IPv6{})) = True
        aaaaDE _ = False
        nullCase [] = [DEonlyNS (nsDomain de)]
        nullCase es@(_ : _) = es

-- {-# ANN rootHint ("HLint: ignore Use tuple-section") #-}
rootHint :: Delegation
rootHint =
    fromMaybe
        (error "rootHint: bad configuration.")
        $ takeDelegationSrc (nsList "." (,) ns) [] as
  where
    (ns, as) = rootServers

data MayDelegation
    = NoDelegation {- no delegation information -}
    | HasDelegation Delegation

mayDelegation :: a -> (Delegation -> a) -> MayDelegation -> a
mayDelegation n h md = case md of
    NoDelegation -> n
    HasDelegation d -> h d

-- 反復検索
-- 繰り返し委任情報をたどって目的の答えを知るはずの権威サーバー群を見つける
iterative :: Delegation -> Domain -> DNSQuery Delegation
iterative sa n = iterative_ 0 sa $ reverse $ DNS.superDomains n

iterative_ :: Int -> Delegation -> [Domain] -> DNSQuery Delegation
iterative_ _ nss0 [] = return nss0
iterative_ dc nss0 (x : xs) =
    {- If NS is not returned, the information of the same NS is used for the child domain. or.jp and ad.jp are examples of this case. -}
    step nss0 >>= mayDelegation (recurse nss0 xs) (`recurse` xs)
  where
    recurse = iterative_ dc {- sub-level delegation. increase dc only not sub-level case. -}
    name = x

    lookupNX :: ContextT IO Bool
    lookupNX = isJust <$> lookupCache name Cache.NX

    stepQuery :: Delegation -> DNSQuery MayDelegation
    stepQuery nss@Delegation{..} = do
        let zone = delegationZone
            dnskeys = delegationDNSKEY
        lift . logLn Log.DEMO $
            "zone: " ++ show zone ++ ":\n" ++ ppDelegation delegationNS
        sas <- delegationIPs dc nss {- When the same NS information is inherited from the parent domain, balancing is performed by re-selecting the NS address. -}
        lift . logLn Log.DEMO . unwords $
            ["iterative: query", show (name, A), "with selected addresses:"]
                ++ [show sa | sa <- sas]
        let dnssecOK = not (null delegationDS) && not (null delegationDNSKEY)
        {- Use `A` for iterative queries to the authoritative servers during iterative resolution.
           See the following document:
           QNAME Minimisation Examples: https://datatracker.ietf.org/doc/html/rfc9156#section-4 -}
        msg <- norec dnssecOK sas name A
        let withNoDelegation handler = mayDelegation handler (return . HasDelegation)
            sharedHandler = subdomainShared dc nss name msg
            cacheHandler = cacheNoDelegation zone dnskeys name msg $> NoDelegation
        delegationWithCache zone dnskeys name msg
            >>= withNoDelegation sharedHandler
            >>= lift . withNoDelegation cacheHandler

    step :: Delegation -> DNSQuery MayDelegation
    step nss = do
        let withNXC nxc
                | nxc = return NoDelegation
                | otherwise = stepQuery nss
        md <- maybe (withNXC =<< lift lookupNX) return =<< lift (lookupDelegation name)
        let fills d = fillsDNSSEC dc nss d
        mayDelegation (return NoDelegation) (fmap HasDelegation . fills) md

-- If Nothing, it is a miss-hit against the cache.
-- If Just NoDelegation, cache hit but no delegation information.
lookupDelegation :: Domain -> ContextT IO (Maybe MayDelegation)
lookupDelegation dom = do
    disableV6NS <- asks disableV6NS_
    let lookupDEs ns = do
            let deListA =
                    rrListWith
                        A
                        (`DNS.rdataField` DNS.a_ipv4)
                        ns
                        (\v4 _ -> DEwithAx ns (IPv4 v4))
                deListAAAA =
                    rrListWith
                        AAAA
                        (`DNS.rdataField` DNS.aaaa_ipv6)
                        ns
                        (\v6 _ -> DEwithAx ns (IPv6 v6))

            lk4 <- fmap (deListA . fst) <$> lookupCache ns A
            lk6 <- fmap (deListAAAA . fst) <$> lookupCache ns AAAA
            return $ case lk4 <> lk6 of
                Nothing
                    | ns `DNS.isSubDomainOf` dom -> [] {- miss-hit with sub-domain case cause iterative loop, so return null to skip this NS -}
                    | otherwise -> [DEonlyNS ns {- the case both A and AAAA are miss-hit -}]
                Just as -> as {- just return address records. null case is wrong cache, so return null to skip this NS -}
        noCachedV4NS es = disableV6NS && null (v4DEntryList es)
        fromDEs es
            | noCachedV4NS es = Nothing
            {- all NS records for A are skipped under disableV6NS, so handle as miss-hit NS case -}
            | otherwise =
                (\des -> HasDelegation $ Delegation dom des [] []) <$> uncons es
        {- Nothing case, all NS records are skipped, so handle as miss-hit NS case -}
        getDelegation :: ([ResourceRecord], a) -> ContextT IO (Maybe MayDelegation)
        getDelegation (rrs, _) = do
            {- NS cache hit -}
            let nss = sort $ nsList dom const rrs
            case nss of
                [] -> return $ Just NoDelegation {- hit null NS list, so no delegation -}
                _ : _ -> fromDEs . concat <$> mapM lookupDEs nss

    maybe (return Nothing) getDelegation =<< lookupCache dom NS

-- Caching while retrieving delegation information from the authoritative server's reply
delegationWithCache
    :: Domain -> [RD_DNSKEY] -> Domain -> DNSMessage -> DNSQuery MayDelegation
delegationWithCache zoneDom dnskeys dom msg = do
    (verifyMsg, verifyColor, raiseOnFailure, dss, cacheDS) <- withSection rankedAuthority msg $ \rrs rank -> do
        let (dsrds, dsRRs) = unzip $ rrListWith DS DNS.fromRData dom (,) rrs
        (rrset, cacheDS) <-
            lift $ verifyAndCache dnskeys dsRRs (rrsigList dom DS rrs) rank
        let (verifyMsg, verifyColor, raiseOnFailure)
                | null nsps = ("no delegation", Nothing, pure ())
                | null dsrds = ("delegation - no DS, so no verify", Just Yellow, pure ())
                | rrsetVerified rrset =
                    ("delegation - verification success - RRSIG of DS", Just Green, pure ())
                | otherwise =
                    ( "delegation - verification failed - RRSIG of DS"
                    , Just Red
                    , throwDnsError DNS.ServerFailure
                    )
        return
            ( verifyMsg
            , verifyColor
            , raiseOnFailure
            , if rrsetVerified rrset then dsrds else []
            , cacheDS
            )

    let found x = do
            cacheDS
            cacheNS
            cacheAdds
            clogLn Log.DEMO Nothing $ ppDelegation (delegationNS x)
            return x

    lift . clogLn Log.DEMO verifyColor $
        "delegationWithCache: " ++ domTraceMsg ++ ", " ++ verifyMsg
    raiseOnFailure
    lift . maybe (pure NoDelegation) (fmap HasDelegation . found) $
        takeDelegationSrc nsps dss adds {- There is delegation information only when there is a selectable NS -}
  where
    domTraceMsg = show zoneDom ++ " -> " ++ show dom

    (nsps, cacheNS) = withSection rankedAuthority msg $ \rrs rank ->
        let nsps_ = nsList dom (,) rrs in (nsps_, cacheNoRRSIG (map snd nsps_) rank)

    (adds, cacheAdds) = withSection rankedAdditional msg $ \rrs rank ->
        let axs = filter match rrs in (axs, cacheSection axs rank)
      where
        match rr = rrtype rr `elem` [A, AAAA] && rrname rr `Set.member` nsSet
        nsSet = Set.fromList $ map fst nsps

{- Workaround delegation for one authoritative server has both domain zone and sub-domain zone -}
subdomainShared
    :: Int -> Delegation -> Domain -> DNSMessage -> DNSQuery MayDelegation
subdomainShared dc nss dom msg = withSection rankedAuthority msg $ \rrs rank -> do
    let soaRRs =
            rrListWith SOA (DNS.fromRData :: RData -> Maybe DNS.RD_SOA) dom (\_ x -> x) rrs
        getWorkaround = fillsDNSSEC dc nss (Delegation dom (delegationNS nss) [] [])
        verifySOA = do
            d <- getWorkaround
            let dnskey = delegationDNSKEY d
            case dnskey of
                [] -> return $ HasDelegation d
                _ : _ -> do
                    (rrset, _) <- lift $ verifyAndCache dnskey soaRRs (rrsigList dom SOA rrs) rank
                    if rrsetVerified rrset
                        then return $ HasDelegation d
                        else do
                            lift . logLn Log.WARN . unwords $
                                [ "subdomainShared:"
                                , show dom ++ ":"
                                , "verification error. invalid SOA:"
                                , show soaRRs
                                ]
                            lift . clogLn Log.DEMO (Just Red) $
                                show dom ++ ": verification error. invalid SOA"
                            throwDnsError DNS.ServerFailure

    case soaRRs of
        [] -> return NoDelegation {- not workaround fallbacks -}
        {- When `A` records are found, indistinguishable from the A definition without sub-domain cohabitation -}
        [_] -> verifySOA
        _ : _ : _ -> do
            lift . logLn Log.WARN . unwords $
                [ "subdomainShared:"
                , show dom ++ ":"
                , "multiple SOAs are found:"
                , show soaRRs
                ]
            lift . logLn Log.DEMO $ show dom ++ ": multiple SOA: " ++ show soaRRs
            throwDnsError DNS.ServerFailure

fillsDNSSEC :: Int -> Delegation -> Delegation -> DNSQuery Delegation
fillsDNSSEC dc nss d = do
    filled@Delegation{..} <- fillDelegationDNSKEY dc =<< fillDelegationDS dc nss d
    when (not (null delegationDS) && null delegationDNSKEY) $ do
        lift . logLn Log.WARN . unwords $
            [ "fillsDNSSEC:"
            , show delegationZone ++ ":"
            , "DS is not null, and DNSKEY is null"
            ]
        lift . clogLn Log.DEMO (Just Red) $
            show delegationZone
                ++ ": verification error. dangling DS chain. DS exists, and DNSKEY does not exists"
        throwDnsError DNS.ServerFailure
    return filled

fillDelegationDS :: Int -> Delegation -> Delegation -> DNSQuery Delegation
fillDelegationDS dc src dest
    | null $ delegationDNSKEY src = return dest {- no DNSKEY, not chained -}
    | null $ delegationDS src = return dest {- no DS, not chained -}
    | not $ null $ delegationDS dest = return dest {- already filled -}
    | otherwise = do
        maybe query (lift . fill . toDSs)
            =<< lift (lookupCache (delegationZone dest) DS)
  where
    toDSs (rrs, _rank) = rrListWith DS DNS.fromRData (delegationZone dest) const rrs
    fill dss = return dest{delegationDS = dss}
    query = do
        ips <- delegationIPs dc src
        let nullIPs = logLn Log.WARN "fillDelegationDS: ip list is null" *> return dest
            domTraceMsg = show (delegationZone src) ++ " -> " ++ show (delegationZone dest)
            verifyFailed es = do
                lift (logLn Log.WARN $ "fillDelegationDS: " ++ es)
                throwDnsError DNS.ServerFailure
            result (e, vinfo) = do
                let traceLog (verifyColor, verifyMsg) =
                        lift . clogLn Log.DEMO (Just verifyColor) $
                            "fill delegation - " ++ verifyMsg ++ ": " ++ domTraceMsg
                maybe (pure ()) traceLog vinfo
                either verifyFailed fill e
        if null ips
            then lift nullIPs
            else result =<< queryDS (delegationDNSKEY src) ips (delegationZone dest)

queryDS
    :: [RD_DNSKEY]
    -> [IP]
    -> Domain
    -> DNSQuery (Either String [RD_DS], (Maybe (Color, String)))
queryDS dnskeys ips dom = do
    msg <- norec True ips dom DS
    withSection rankedAnswer msg $ \rrs rank -> do
        let (dsrds, dsRRs) = unzip $ rrListWith DS DNS.fromRData dom (,) rrs
            rrsigs = rrsigList dom DS rrs
        (rrset, cacheDS) <- lift $ verifyAndCache dnskeys dsRRs rrsigs rank
        let verifyResult
                | null dsrds = return (Right [], Nothing {- no DS, so no verify -})
                | rrsetVerified rrset =
                    lift cacheDS
                        *> return (Right dsrds, Just (Green, "verification success - RRSIG of DS"))
                | otherwise =
                    return
                        ( Left "queryDS: verification failed - RRSIG of DS"
                        , Just (Red, "verification failed - RRSIG of DS")
                        )
        verifyResult

fillDelegationDNSKEY :: Int -> Delegation -> DNSQuery Delegation
fillDelegationDNSKEY _ d@Delegation{delegationDS = []} = return d {- DS(Delegation Signer) does not exist -}
fillDelegationDNSKEY _ d@Delegation{delegationDS = _ : _, delegationDNSKEY = _ : _} = return d {- already filled -}
fillDelegationDNSKEY dc d@Delegation{delegationDS = _ : _, delegationDNSKEY = [], ..} =
    maybe query (lift . fill . toDNSKEYs)
        =<< lift (lookupCache delegationZone DNSKEY)
  where
    toDNSKEYs (rrs, _) = rrListWith DNSKEY DNS.fromRData delegationZone const rrs
    fill dnskeys = return d{delegationDNSKEY = dnskeys}
    query = do
        ips <- delegationIPs dc d
        let nullIPs = logLn Log.WARN "fillDelegationDNSKEY: ip list is null" *> return d
            verifyFailed es = logLn Log.WARN ("fillDelegationDNSKEY: " ++ es) *> return d
        if null ips
            then lift nullIPs
            else
                lift . either verifyFailed fill
                    =<< cachedDNSKEY (delegationDS d) ips delegationZone

---

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

rrsetNull :: RRset -> Bool
rrsetNull = null . rrsRDatas

rrListFromRRset :: RequestDO -> RRset -> [ResourceRecord]
rrListFromRRset reqDO RRset{..} = case reqDO of
    NoDnssecOK -> rrs
    DnssecOK -> case rrsRDatas of
        [] -> []
        _ : _ -> rrs ++ sigs
  where
    rrs =
        [ ResourceRecord rrsName rrsType rrsClass rrsTTL rd
        | rd <- rrsRDatas
        ]
    sigs =
        [ ResourceRecord rrsName RRSIG rrsClass rrsTTL (DNS.toRData sig)
        | sig <- rrsGoodSigs
        ]

{-# WARNING
    recoverRRset
    "remove this definition after supporting lookups of rrset from cache"
    #-}
recoverRRset :: [ResourceRecord] -> Maybe RRset
recoverRRset rrs =
    either (const Nothing) (\cps -> Just $ cps k) $
        SEC.canonicalRRsetSorted sortedRRs
  where
    k dom typ cls ttl rds = RRset dom typ cls ttl rds []
    (_, sortedRRs) = unzip $ SEC.sortCanonical rrs

---

---

{- Get the answer DNSMessage from the authoritative server.
   Note about flags in request to an authoritative server.
  * RD (Recursion Desired) must be 0 for request to authoritative server
  * EDNS must be enable for DNSSEC OK request -}
norec :: Bool -> [IP] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnsssecOK aservers name typ = dnsQueryT $ \cxt _qctl -> do
    let ris =
            [ defaultResolvInfo
                { rinfoHostName = show aserver
                , rinfoActions =
                    defaultResolvActions
                        { ractionGenId = idGen_ cxt
                        , ractionGetTime = currentSeconds_ cxt
                        , ractionLog = logLines_ cxt
                        }
                }
            | aserver <- aservers
            ]
        renv =
            ResolvEnv
                { renvResolver = udpTcpResolver 3 (32 * 1024) -- 3 is retry
                , renvConcurrent = True -- should set True if multiple RIs are provided
                , renvResolvInfos = ris
                }
        q = Question name typ classIN
        doFlagSet
            | dnsssecOK = FlagSet
            | otherwise = FlagClear
        qctl = DNS.rdFlag FlagClear <> DNS.doFlag doFlagSet
    either
        (Left . DnsError)
        ( \res -> handleResponseError Left Right $ DNS.replyDNSMessage (DNS.resultReply res)
        )
        <$> E.try (DNS.resolve renv q qctl)

-- Filter authoritative server addresses from the delegation information.
-- If the resolution result is NODATA, IllegalDomain is returned.
delegationIPs :: Int -> Delegation -> DNSQuery [IP]
delegationIPs dc Delegation{..} = do
    disableV6NS <- lift $ asks disableV6NS_

    let ipnum = 4
        ips = takeDEntryIPs disableV6NS delegationNS

        takeNames (DEonlyNS name) xs
            | not $
                name `DNS.isSubDomainOf` delegationZone =
                name : xs {- skip sub-domain without glue to avoid loop -}
        takeNames _ xs = xs

        names = foldr takeNames [] $ uncurry (:) delegationNS

        result
            | not (null ips) = selectIPs ipnum ips
            | not (null names) = do
                mayName <- randomizedSelect names
                let neverReach = do
                        lift $ logLn Log.DEMO $ "delegationIPs: never reach this action."
                        throwDnsError DNS.ServerFailure
                maybe neverReach (fmap ((: []) . fst) . resolveNS disableV6NS dc) mayName
            | disableV6NS && not (null allIPs) = do
                lift . logLn Log.DEMO . concat $
                    [ "delegationIPs: server-fail: domain: "
                    , show delegationZone
                    , ", delegation is empty."
                    ]
                throwDnsError DNS.ServerFailure
            | otherwise = do
                lift . logLn Log.DEMO . concat $
                    [ "delegationIPs: illegal-domain: "
                    , show delegationZone
                    , ", delegation is empty."
                    , " without glue sub-domains: "
                    , show subNames
                    ]
                throwDnsError DNS.IllegalDomain
          where
            allIPs = takeDEntryIPs False delegationNS

        takeSubNames (DEonlyNS name) xs
            | name `DNS.isSubDomainOf` delegationZone =
                name : xs {- sub-domain name without glue -}
        takeSubNames _ xs = xs
        subNames = foldr takeSubNames [] $ uncurry (:) delegationNS

    result

takeDEntryIPs :: Bool -> NE DEntry -> [IP]
takeDEntryIPs disableV6NS des = unique $ foldr takeDEntryIP [] (fst des : snd des)
  where
    unique = Set.toList . Set.fromList
    takeDEntryIP (DEonlyNS{}) xs = xs
    takeDEntryIP (DEwithAx _ ip@(IPv4{})) xs = ip : xs
    takeDEntryIP (DEwithAx _ ip@(IPv6{})) xs
        | disableV6NS = xs
        | otherwise = ip : xs

resolveNS :: Bool -> Int -> Domain -> DNSQuery (IP, ResourceRecord)
resolveNS disableV6NS dc ns = do
    let axPairs = axList disableV6NS (== ns) (,)

        lookupAx
            | disableV6NS = lk4
            | otherwise = join $ randomizedSelectN (lk46, [lk64])
          where
            lk46 = lk4 +? lk6
            lk64 = lk6 +? lk4
            lk4 = lookupCache ns A
            lk6 = lookupCache ns AAAA
            lx +? ly = maybe ly (return . Just) =<< lx

        query1Ax
            | disableV6NS = q4
            | otherwise = join $ randomizedSelectN (q46, [q64])
          where
            q46 = q4 +!? q6
            q64 = q6 +!? q4
            q4 = querySection A
            q6 = querySection AAAA
            qx +!? qy = do
                xs <- qx
                if null xs then qy else pure xs
            querySection typ =
                lift . cacheAnswerAx
                    =<< resolveJustDC (succ dc) ns typ {- resolve for not sub-level delegation. increase dc (delegation count) -}
            cacheAnswerAx (msg, _) = withSection rankedAnswer msg $ \rrs rank -> do
                let ps = axPairs rrs
                cacheSection (map snd ps) rank
                return ps

        resolveAXofNS :: DNSQuery (IP, ResourceRecord)
        resolveAXofNS = do
            let failEmptyAx
                    | disableV6NS = do
                        lift . logLn Log.WARN $
                            "resolveNS: server-fail: NS: " ++ show ns ++ ", address is empty."
                        throwDnsError DNS.ServerFailure
                    | otherwise = do
                        lift . logLn Log.WARN $
                            "resolveNS: illegal-domain: NS: " ++ show ns ++ ", address is empty."
                        throwDnsError DNS.IllegalDomain
            maybe failEmptyAx pure
                =<< randomizedSelect {- 失敗時: NS に対応する A の返答が空 -}
                =<< maybe query1Ax (pure . axPairs . fst)
                =<< lift lookupAx

    resolveAXofNS

---

