{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Resolve (
    runResolve,
    resolveByCache,
    resolve,
) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (QueryControls (..))
import qualified DNS.Log as Log
import DNS.RRCache (Ranking (RankAdditional), rankedAnswer)
import qualified DNS.RRCache as Cache
import DNS.Types
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Local
import DNS.Iterative.Query.ResolveJust
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils
import qualified DNS.Iterative.Query.Verify as Verify

-- 最終的な解決結果を得る
runResolve
    :: Env
    -> Question
    -> QueryControls
    -> IO (Either QueryError (([RRset], Domain), Either ResultRRS (ResultRRS' DNSMessage)))
runResolve cxt q qctl = runDNSQuery (resolve q) cxt $ queryContext q qctl

resolveByCache
    :: Question
    -> DNSQuery (([RRset], Domain), Either ResultRRS (ResultRRS' ()))
resolveByCache =
    resolveLogic
        "cache"
        (\_ -> pure ((), [], []))
        (\_ _ -> pure $ Right ((), [], []))

{- 反復検索を使って最終的な権威サーバーからの DNSMessage を得る.
   目的の TYPE の RankAnswer 以上のキャッシュ読み出しが得られた場合はそれが結果となる.
   目的の TYPE が CNAME 以外の場合、結果が CNAME なら繰り返し解決する. その際に CNAME レコードのキャッシュ書き込みを行なう.
   目的の TYPE の結果レコードをキャッシュする. -}
resolve
    :: Question
    -> DNSQuery (([RRset], Domain), Either ResultRRS (ResultRRS' DNSMessage))
resolve = resolveLogic "query" resolveCNAME resolveTYPE

{- FOURMOLU_DISABLE -}
{- |
   result value of resolveLogic:
   * Left ResultRRS                 - cached result
   * Right (ResultRRS' a)           - queried result like (ResultRRS' DNSMessage)
   * QueryError                     - other errors   -}
resolveLogic
    :: String
    -> (Domain -> DNSQuery (ResultRRS' a))
    -> (Domain -> TYPE -> DNSQuery (Either (Domain, RRset) (ResultRRS' a)))
    -> Question
    -> DNSQuery (([RRset], Domain), Either ResultRRS (ResultRRS' a))
resolveLogic logMark cnameHandler typeHandler q@(Question n0 typ cls) = do
    env <- ask
    maybe (called *> notLocal) local' =<< takeLocalResult env q
  where
    local' result = pure (([], n0), Left result)
    notLocal
        | cls /= IN        = pure (([], n0), Left (DNS.NoErr, [], []))  {- not support other than IN -}
        | typ == Cache.ERR = pure (([], n0), Left (DNS.NoErr, [], []))
        | typ == ANY       = pure (([], n0), Left (DNS.NotImpl, [], []))
        | typ == CNAME     = justCNAME n0
        | otherwise        = recCNAMEs 0 n0 id
    logLines_ lv = logLines lv . pindents ("resolve-with-cname: " ++ logMark)
    logLn_ lv s = logLines_ lv [s]
    called = do
        let qbitstr tag sel tbl = ((tag ++ ":") ++) . maybe "" id . (`lookup` tbl) <$> asksQC sel
        do_ <- qbitstr "DnssecOK"           requestDO_  [(DnssecOK,           "1"), (NoDnssecOK,           "0")]
        cd_ <- qbitstr "CheckDisabled"      requestCD_  [(CheckDisabled,      "1"), (NoCheckDisabled,      "0")]
        ad_ <- qbitstr "AuthenticatedData"  requestAD_  [(AuthenticatedData,  "1"), (NoAuthenticatedData,  "0")]
        logLines_ Log.DEMO [unwords [show n0, show typ, show cls], intercalate ", " [do_, cd_, ad_]]
    justCNAME bn = do
        let noCache = do
                result <- cnameHandler bn
                pure (([], bn), Right result)

            withERRC (rc, soa)          = pure (([], bn), Left (rc, [], soa))
            cachedCNAME (rc, rrs, soa)  = pure (([], bn), Left (rc, rrs, soa))

            negative soa _rank  = (DNS.NoErr, [], [soa])
            noSOA rc            = (rc, [], [])

        maybe
            (maybe noCache withERRC =<< lookupERR bn)
            {- target RR is not CNAME destination, but CNAME result is NoErr -}
            (cachedCNAME . foldLookupResult negative noSOA (\cname -> (DNS.NoErr, [cname], [])))
            =<< lookupType bn CNAME

    -- CNAME 以外のタイプの検索について、CNAME のラベルで検索しなおす.
    -- recCNAMEs :: Int -> Domain -> [RRset] -> DNSQuery (([RRset], Domain), Either Result a)
    recCNAMEs cc bn dcnRRsets
        | cc > mcc = do
            logLn_ Log.WARN $ "cname chain limit exceeded: " ++ show (n0, typ)
            failWithCacheOrigName Cache.RankAnswer DNS.ServerFailure
        | otherwise = do
            let recCNAMEs_ (cn, cnRRset) = logLn_ Log.DEMO (show cn) *> recCNAMEs (succ cc) cn (dcnRRsets . (cnRRset :))
                noCache = either recCNAMEs_ (pure . (,) (dcnRRsets [], bn) . Right) =<< typeHandler bn typ

                withERRC (rc, soa) = pure ((dcnRRsets [], bn), Left (rc, [], soa))

                noTypeCache =
                    maybe
                        (maybe noCache withERRC =<< lookupERR bn)
                        recCNAMEs_ {- recurse with cname cache -}
                        =<< (withCN =<<) . joinLKR <$> lookupType bn CNAME
                  where
                    {- when CNAME has NODATA, do not loop with CNAME domain -}
                    joinLKR = (foldLookupResult (\_ _ -> Nothing) (\_ -> Nothing) Just =<<)
                    withCN cnRRset = do
                        (cn, _) <- uncons cns
                        Just (cn, cnRRset)
                      where
                        cns = [cn | rd <- rrsRDatas cnRRset, Just cn <- [DNS.rdataField rd DNS.cname_domain]]

                cachedType (rc, tyRRs, soa) = pure ((dcnRRsets [], bn), Left (rc, tyRRs, soa))

            maybe
                noTypeCache
                ( cachedType
                    . foldLookupResult
                        (\soa _rank -> (DNS.NoErr, [], [soa]))
                        (\rc -> (rc, [], []))
                        (\xrrs -> (DNS.NoErr, [xrrs], [] {- return cached result with target typ -}))
                )
                =<< lookupType bn typ
      where
        mcc = maxCNameChain

    lookupERR :: Domain -> DNSQuery (Maybe (RCODE, [RRset]))
    lookupERR name =
        maybe (pure Nothing) (foldLookupResult soah (\rc -> pure $ Just (rc, [])) inconsistent)
            =<< lookupType name Cache.ERR
      where
        soah soa rank = pure $ Just (NameErr, [soa | rank > RankAdditional])
        inconsistent rrs = do
            logLn_ Log.WARN $ "inconsistent ERR cache found: dom=" ++ show name ++ ", " ++ show rrs
            return Nothing

    lookupType bn t = maybe (pure empty) filterLookup =<< lookupRRsetEither logMark bn t
    filterLookup (x, rank) = do
        reqCD <- asksQC requestCD_
        pure $ do
            guardReply rank
            guardLookup reqCD x
            Just x
    --
    guardLookup reqCD = foldLookupResult (guardNegative reqCD) (guardNegativeNoSOA reqCD) (guardPositive reqCD)
    guardNegative reqCD soa soaRank = guardReply soaRank *> guardMayVerified reqCD soa
    guardNegativeNoSOA CheckDisabled   _rc = empty    {- query again for verification error -}
    guardNegativeNoSOA NoCheckDisabled _rc = pure ()
    guardPositive reqCD rrset = guardMayVerified reqCD rrset
    --
    guardMayVerified reqCD rrset = mayVerifiedRRS (pure ()) guardCD (\_ -> empty) (\_ -> pure ()) $ rrsMayVerified rrset
      where guardCD = guardAllowCachedCD reqCD
    guardAllowCachedCD CheckDisabled    = pure ()
    guardAllowCachedCD NoCheckDisabled  = empty
    {- 最も低い ranking は reply の answer に利用しない
     - https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1 -}
    guardReply rank = guard (rank > RankAdditional)
{- FOURMOLU_ENABLE -}

{- CNAME のレコードを取得し、キャッシュする -}
resolveCNAME :: Domain -> DNSQuery (ResultRRS' DNSMessage)
resolveCNAME bn = do
    (msg, d) <- resolveExact bn CNAME
    uncurry ((,,) msg) <$> cacheAnswer d bn CNAME msg

{- 目的の TYPE のレコードを取得できた場合には、結果の DNSMessage と RRset を返す.
   結果が CNAME の場合、そのドメイン名と RRset を返す.
   どちらの場合も、結果のレコードをキャッシュする. -}
{- returns: result msg, cname, verified answer, verified authority -}
resolveTYPE :: Domain -> TYPE -> DNSQuery (Either (Domain, RRset) (ResultRRS' DNSMessage))
resolveTYPE bn typ = do
    (msg, delegation@Delegation{..}) <- resolveExact bn typ
    let cnDomain rr = DNS.rdataField (rdata rr) DNS.cname_domain
        nullCNAME = Right . uncurry ((,,) msg) <$> cacheAnswer delegation bn typ msg
        ncCNAME _ncLog = pure $ Right (msg, [], [])
        ansHasTYPE = any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg
        mkResult cnames cnameRRset cacheCNAME = do
            let cninfo = (,) <$> (fst <$> uncons cnames) <*> pure cnameRRset
            when ansHasTYPE $ throwDnsError DNS.UnexpectedRDATA {- CNAME と目的の TYPE が同時に存在した場合はエラー -}
            cacheCNAME $> maybe (Right (msg, [], [])) Left cninfo
    reqCD <- asksQC requestCD_
    Verify.cases reqCD delegationZone delegationDNSKEY rankedAnswer msg bn CNAME cnDomain nullCNAME ncCNAME mkResult

maxCNameChain :: Int
maxCNameChain = 16
