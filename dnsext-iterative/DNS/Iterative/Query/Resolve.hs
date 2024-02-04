{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Resolve (
    runResolve,
    resolve,
    resolveLogic,
) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (QueryControls (..))
import qualified DNS.Log as Log
import DNS.RRCache (
    Ranking (RankAdditional),
    rankedAnswer,
 )
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
    -> IO
        ( Either
            QueryError
            (([RRset], Domain), Either ResultRRS (DNSMessage, ([RRset], [RRset])))
        )
runResolve cxt q cd = runDNSQuery (resolve q) cxt $ QueryContext cd q

{- 反復検索を使って最終的な権威サーバーからの DNSMessage を得る.
   目的の TYPE の RankAnswer 以上のキャッシュ読み出しが得られた場合はそれが結果となる.
   目的の TYPE が CNAME 以外の場合、結果が CNAME なら繰り返し解決する. その際に CNAME レコードのキャッシュ書き込みを行なう.
   目的の TYPE の結果レコードをキャッシュする. -}
resolve
    :: Question
    -> DNSQuery (([RRset], Domain), Either ResultRRS (DNSMessage, ([RRset], [RRset])))
resolve = resolveLogic "query" resolveCNAME resolveTYPE

{- FOURMOLU_DISABLE -}
{- |
   result value of resolveLogic:
   * Left ResultRRS                 - cached result
   * Right (a, ([RRset], [RRset]))  - queried result like (DNSMessage, ([RRset], [RRset]))
   * QueryError                     - other errors   -}
resolveLogic
    :: String
    -> (Domain -> DNSQuery (a, ([RRset], [RRset])))
    -> (Domain -> TYPE -> DNSQuery (a, Maybe (Domain, RRset), ([RRset], [RRset])))
    -> Question
    -> DNSQuery (([RRset], Domain), Either ResultRRS (a, ([RRset], [RRset])))
resolveLogic logMark cnameHandler typeHandler q@(Question n0 typ cls) = do
    env <- lift ask
    maybe (called *> notLocal) local =<< takeLocalResult env q
  where
    local result = return (([], n0), Left result)
    notLocal
        | cls /= IN        = pure (([], n0), Left (DNS.NoErr, [], []))  {- not support other than IN -}
        | typ == Cache.NX  = pure (([], n0), Left (DNS.NoErr, [], []))
        | typ == CNAME     = justCNAME n0
        | otherwise        = recCNAMEs 0 n0 id
    logLn_ lv s = logLn lv $ "resolve-with-cname: " ++ logMark ++ ": " ++ s
    called = lift $ logLn_ Log.DEBUG $ show (n0, typ, cls)
    justCNAME bn = do
        let noCache = do
                result <- cnameHandler bn
                pure (([], bn), Right result)

            withNXC soa                 = pure (([], bn), Left (DNS.NameErr, [], soa))
            cachedCNAME (rc, rrs, soa)  = pure (([], bn), Left (rc, rrs, soa))

            negative soa _rank  = (DNS.NoErr, [], [soa])
            noSOA rc            = (rc, [], [])

        maybe
            (maybe noCache withNXC =<< lift (lookupNX bn))
            {- target RR is not CNAME destination, but CNAME result is NoErr -}
            (cachedCNAME . foldLookupResult negative noSOA (\cname -> (DNS.NoErr, [cname], [])))
            =<< lift (lookupType bn CNAME)

    -- CNAME 以外のタイプの検索について、CNAME のラベルで検索しなおす.
    -- recCNAMEs :: Int -> Domain -> [RRset] -> DNSQuery (([RRset], Domain), Either Result a)
    recCNAMEs cc bn dcnRRsets
        | cc > mcc = do
            lift $ logLn_ Log.WARN $ "cname chain limit exceeded: " ++ show (n0, typ)
            failWithCacheOrigQ Cache.RankAnswer DNS.ServerFailure
        | otherwise = do
            let recCNAMEs_ (cn, cnRRset) = recCNAMEs (succ cc) cn (dcnRRsets . (cnRRset :))
                noCache = do
                    (msg, cname, vsec) <- typeHandler bn typ
                    maybe (pure ((dcnRRsets [], bn), Right (msg, vsec))) recCNAMEs_ cname

                withNXC soa = pure ((dcnRRsets [], bn), Left (DNS.NameErr, [], soa))

                noTypeCache =
                    maybe
                        (maybe noCache withNXC =<< lift (lookupNX bn))
                        recCNAMEs_ {- recurse with cname cache -}
                        =<< lift ((withCN =<<) . joinLKR <$> lookupType bn CNAME)
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
                =<< lift (lookupType bn typ)
      where
        mcc = maxCNameChain

    lookupNX :: Domain -> ContextT IO (Maybe [RRset])
    lookupNX bn =
        maybe (return Nothing) (foldLookupResult (\soa _rank -> pure $ Just [soa]) (\_rc -> pure $ Just []) inconsistent)
            =<< lookupType bn Cache.NX
      where
        inconsistent rrs = do
            logLn_ Log.WARN $ "inconsistent NX cache found: dom=" ++ show bn ++ ", " ++ show rrs
            return Nothing

    lookupType bn t = (replyRank =<<) <$> lookupRRsetEither logMark bn t
    replyRank (x, rank)
        -- 最も低い ranking は reply の answer に利用しない
        -- https://datatracker.ietf.org/doc/html/rfc2181#section-5.4.1
        | rank <= RankAdditional = Nothing
        | otherwise = Just x
{- FOURMOLU_ENABLE -}

{- CNAME のレコードを取得し、キャッシュする -}
resolveCNAME :: Domain -> DNSQuery (DNSMessage, ([RRset], [RRset]))
resolveCNAME bn = do
    (msg, d) <- resolveExact bn CNAME
    (,) msg <$> cacheAnswer d bn CNAME msg

{- 目的の TYPE のレコードの取得を試み、結果の DNSMessage を返す.
   結果が CNAME なら、その RR も返す.
   どちらの場合も、結果のレコードをキャッシュする. -}
{- returns: result msg, cname, verified answer, verified authority -}
resolveTYPE :: Domain -> TYPE -> DNSQuery (DNSMessage, Maybe (Domain, RRset), ([RRset], [RRset]))
resolveTYPE bn typ = do
    (msg, delegation@Delegation{..}) <- resolveExact bn typ
    let cnDomain rr = DNS.rdataField (rdata rr) DNS.cname_domain
        nullCNAME = (,,) msg Nothing <$> cacheAnswer delegation bn typ msg
        ncCNAME = pure (msg, Nothing, ([], []))
        ansHasTYPE = any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg
        mkResult cnames cnameRRset cacheCNAME = do
            let cninfo = (,) <$> (fst <$> uncons cnames) <*> pure cnameRRset
            when ansHasTYPE $ throwDnsError DNS.UnexpectedRDATA {- CNAME と目的の TYPE が同時に存在した場合はエラー -}
            lift cacheCNAME $> (msg, cninfo, ([], []))
    Verify.with delegationDNSKEY rankedAnswer msg bn CNAME cnDomain nullCNAME ncCNAME mkResult

maxCNameChain :: Int
maxCNameChain = 16
