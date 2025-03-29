{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

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
import DNS.RRCache (Ranking (RankAdditional))
import qualified DNS.RRCache as Cache
import DNS.Types
import qualified DNS.Types as DNS

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Cache
import DNS.Iterative.Query.Class
import DNS.Iterative.Query.Helpers
import DNS.Iterative.Query.ResolveJust
import DNS.Iterative.Query.Types
import DNS.Iterative.Query.Utils

-- 最終的な解決結果を得る
runResolve
    :: Env
    -> Question
    -> QueryControls
    -> IO (Either QueryError (([RRset], Domain), Either ResultRRS (ResultRRS' DNSMessage)))
runResolve cxt q qctl = runDNSQuery (resolve q) cxt $ queryParam q qctl

{- FOURMOLU_DISABLE -}
resolveByCache
    :: Question
    -> DNSQuery (([RRset], Domain), Maybe ResultRRS)
resolveByCache =
    resolveLogic
        "cache" Just (const Nothing)
        (failWithCacheOrigName Cache.RankAnswer ServerFailure) (\_ -> pure ((), [], [])) (\_ _ -> pure $ Right ((), [], []))
{- FOURMOLU_ENABLE -}

{- 反復検索を使って最終的な権威サーバーからの DNSMessage を得る.
   目的の TYPE の RankAnswer 以上のキャッシュ読み出しが得られた場合はそれが結果となる.
   目的の TYPE が CNAME 以外の場合、結果が CNAME なら繰り返し解決する. その際に CNAME レコードのキャッシュ書き込みを行なう.
   目的の TYPE の結果レコードをキャッシュする. -}
resolve
    :: Question
    -> DNSQuery (([RRset], Domain), Either ResultRRS (ResultRRS' DNSMessage))
resolve = resolveLogic "query" Left Right (failWithCacheOrigName Cache.RankAnswer ServerFailure) resolveCNAME resolveTYPE

{- FOURMOLU_DISABLE -}
{- |
   result value of resolveLogic:
   * left   :: ResultRRS -> b       - cached result
   * right  :: ResultRRS' a -> b    - queried result like (ResultRRS' DNSMessage)   -}
resolveLogic
    :: (MonadEnv m, MonadReaderQP m)
    => String
    -> (ResultRRS -> b) -> (ResultRRS' a -> b)
    -> m (([RRset], Domain), b)
    -> (Domain -> m (ResultRRS' a))
    -> (Domain -> TYPE -> m (Either (Domain, RRset) (ResultRRS' a)))
    -> Question
    -> m (([RRset], Domain), b)
resolveLogic logMark left right cnameLimitResult cnameHandler typeHandler (Question n0 typ cls) =
    called >> notLocal
  where
    notLocal
        | cls /= IN        = pure (([], n0), left (DNS.NoErr, [], []))  {- not support other than IN -}
        | typ == Cache.ERR = pure (([], n0), left (DNS.NoErr, [], []))
        | typ == ANY       = pure (([], n0), left (DNS.NotImpl, [], []))
        | typ == CNAME     = justCNAME n0
        | otherwise        = recCNAMEs 0 n0 id
    logLines__ lv = logLines lv . pindents ("resolve: " ++ logMark)
    logLn_ lv s = logLines__ lv [s]
    called = do
        let qbitstr tag sel tbl = ((tag ++ ":") ++) . fromMaybe "" . (`lookup` tbl) <$> asksQP sel
        do_ <- qbitstr "DnssecOK"           requestDO_  [(DnssecOK,           "1"), (NoDnssecOK,           "0")]
        cd_ <- qbitstr "CheckDisabled"      requestCD_  [(CheckDisabled,      "1"), (NoCheckDisabled,      "0")]
        ad_ <- qbitstr "AuthenticatedData"  requestAD_  [(AuthenticatedData,  "1"), (NoAuthenticatedData,  "0")]
        logLines__ Log.DEMO [unwords [show n0, show typ, show cls], intercalate ", " [do_, cd_, ad_]]
    justCNAME bn = do
        let noCache = do
                result <- cnameHandler bn
                pure (([], bn), right result)

            withERRC (rc, soa)          = pure (([], bn), left (rc, [], soa))
            cachedCNAME (rc, rrs, soa)  = pure (([], bn), left (rc, rrs, soa))

            negative soa nsecs _rank  = (DNS.NoErr, [], soa : nsecs)
            noSOA rc                  = (rc, [], [])

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
            cnameLimitResult
        | otherwise = do
            let traceCNAME cn = logLn_ Log.DEMO ("cname: " ++ show bn ++ " -> " ++ show cn)
                recCNAMEs_ (cn, cnRRset) = traceCNAME cn *> recCNAMEs (succ cc) cn (dcnRRsets . (cnRRset :))
                noCache = either recCNAMEs_ (pure . (,) (dcnRRsets [], bn) . right) =<< typeHandler bn typ

                withERRC (rc, soa) = pure ((dcnRRsets [], bn), left (rc, [], soa))

                noTypeCache =
                    maybe
                        (maybe noCache withERRC =<< lookupERR bn)
                        recCNAMEs_ {- recurse with cname cache -}
                        =<< (withCN =<<) . joinLKR <$> lookupType bn CNAME
                  where
                    {- when CNAME has NODATA, do not loop with CNAME domain -}
                    joinLKR = (foldLookupResult (\_ _ _ -> Nothing) (\_ -> Nothing) Just =<<)
                    withCN cnRRset = do
                        (cn, _) <- uncons cns
                        Just (cn, cnRRset)
                      where
                        cns = [cn | rd <- rrsRDatas cnRRset, Just cn <- [DNS.rdataField rd DNS.cname_domain]]

                cachedType (rc, tyRRs, soa) = pure ((dcnRRsets [], bn), left (rc, tyRRs, soa))

            maybe
                noTypeCache
                ( cachedType
                    . foldLookupResult
                        (\soa nsecs _rank -> (DNS.NoErr, [], soa : nsecs))
                        (\rc -> (rc, [], []))
                        (\xrrs -> (DNS.NoErr, [xrrs], [] {- return cached result with target typ -}))
                )
                =<< lookupType bn typ
      where
        mcc = maxCNameChain

    lookupERR name =
        maybe (pure Nothing) (foldLookupResult soah (\rc -> pure $ Just (rc, [])) inconsistent)
            =<< lookupType name Cache.ERR
      where
        {- authority section is cached as RankAdditional, so not applying guardReply -}
        soah soa nsecs _rank = pure $ Just (NameErr, soa : nsecs)
        inconsistent rrs = do
            logLn_ Log.WARN $ "inconsistent ERR cache found: dom=" ++ show name ++ ", " ++ show rrs
            return Nothing

    lookupType bn t = maybe (pure empty) filterLookup =<< lookupRRsetEither logMark bn t
    filterLookup (x, rank) = do
        reqCD <- asksQP requestCD_
        pure $ do
            guardReply rank
            guardLookup reqCD x
            Just x
    --
    guardLookup reqCD = foldLookupResult (guardNegative reqCD) (guardNegativeNoSOA reqCD) (guardPositive reqCD)
    {- {- authority section is cached as RankAdditional, so not applying guard -} guardReply soaRank *> -}
    guardNegative reqCD soa _nsecs _soaRank = guardMayVerified reqCD soa
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

{- FOURMOLU_DISABLE -}
{- 目的の TYPE のレコードを取得できた場合には、結果の DNSMessage と RRset を返す.
   結果が CNAME の場合、そのドメイン名と RRset を返す.
   どちらの場合も、結果のレコードをキャッシュする. -}
{- returns: result msg, cname, verified answer, verified authority -}
resolveTYPE :: Domain -> TYPE -> DNSQuery (Either (Domain, RRset) (ResultRRS' DNSMessage))
resolveTYPE bn typ = do
    (msg, delegation) <- resolveExact bn typ
    let has ty = any ((&&) <$> (== bn) . rrname <*> (== ty) . rrtype) $ DNS.answer msg
        hasCNAME  = has CNAME
        cns cnAns = [(cn, cnRRset) | cnRRset <- cnAns, rd <- rrsRDatas cnRRset, Just cn <- [DNS.rdataField rd DNS.cname_domain]]
        ierr = logLn Log.WARN (pprMessage "resolveTYPE: inconsistent, cnames exists or not" msg) >> throwDnsError ServerFailure
        cnResult (cnAns, _cnAuth) = list ierr (\cn _ -> pure $ Left cn) $ cns cnAns
        dispatch
            | not hasCNAME                   = Right . uncurry ((,,) msg) <$> cacheAnswer delegation bn typ msg
            |     hasCNAME && not (has typ)  = cnResult =<< cacheAnswer delegation bn CNAME msg
            | otherwise                      = throwDnsError UnexpectedRDATA {- CNAME と目的の TYPE が同時に存在した場合はエラー -}
    dispatch
{- FOURMOLU_ENABLE -}

maxCNameChain :: Int
maxCNameChain = 16
