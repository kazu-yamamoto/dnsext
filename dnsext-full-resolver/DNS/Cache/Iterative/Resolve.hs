{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Iterative.Resolve (
    runResolve,
    resolve,
    resolveLogic,
) where

-- GHC packages
import Control.Monad (when)
import Control.Monad.Trans.Class (lift)
import Data.Functor (($>))
import Data.List (uncons)

-- other packages

-- dns packages

import DNS.Do53.Client (
    QueryControls (..),
 )
import DNS.Do53.Memo (
    Ranking (RankAdditional),
    rankedAnswer,
 )
import qualified DNS.Do53.Memo as Cache
import DNS.SEC (
    TYPE,
 )
import qualified DNS.SEC.Verify as SEC
import DNS.Types (
    DNSMessage,
    Domain,
    ResourceRecord (..),
    TYPE (CNAME),
 )
import qualified DNS.Types as DNS

-- this package
import DNS.Cache.Iterative.Cache
import DNS.Cache.Iterative.Helpers
import DNS.Cache.Iterative.ResolveJust
import DNS.Cache.Iterative.Rev
import DNS.Cache.Iterative.Types
import DNS.Cache.Iterative.Utils
import qualified DNS.Cache.Iterative.Verify as Verify
import qualified DNS.Log as Log

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
    logLn_ lv s = logLn lv $ "resolve-with-cname: " ++ logMark ++ ": " ++ s
    called = lift $ logLn_ Log.DEBUG $ show (n0, typ)
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
        | cc > mcc = do
            lift $ logLn_ Log.WARN $ "cname chain limit exceeded: " ++ show (n0, typ)
            throwDnsError DNS.ServerFailure
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
            logLn_ Log.WARN $ "inconsistent NX cache found: dom=" ++ show bn ++ ", " ++ show rrs
            return Nothing

    -- Nothing のときはキャッシュに無し
    -- Just Left のときはキャッシュに有るが CNAME レコード無し
    lookupCNAME :: Domain -> ContextT IO (Maybe (Either [ResourceRecord] (Domain, ResourceRecord)))
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
        nullCNAME = pure $ (,,) msg Nothing <$> cacheAnswer delegation bn typ msg
        ncCNAME = pure $ pure (msg, Nothing, ([], []))
        ansHasTYPE = any ((&&) <$> (== bn) . rrname <*> (== typ) . rrtype) $ DNS.answer msg
        mkResult cnames cnameRRset cacheCNAME = pure $ do
            let cninfo = (,) <$> (fst <$> uncons cnames) <*> pure cnameRRset
            when ansHasTYPE $ throwDnsError DNS.UnexpectedRDATA {- CNAME と目的の TYPE が同時に存在した場合はエラー -}
            lift cacheCNAME $> (msg, cninfo, ([], []))
    verify <- lift $ Verify.withCanonical delegationDNSKEY rankedAnswer msg bn CNAME cnDomain nullCNAME ncCNAME mkResult
    verify

{-# WARNING
    recoverRRset
    "remove this definition after supporting lookups of rrset from cache"
    #-}
recoverRRset :: [ResourceRecord] -> Maybe RRset
recoverRRset rrs =
    either (const Nothing) (\cps -> Just $ cps k) $
        SEC.canonicalRRsetSorted sortedRRs
  where
    k dom typ cls ttl rds = RRset dom typ cls ttl rds NotVerifiedRRS
    (_, sortedRRs) = unzip $ SEC.sortCanonical rrs

maxCNameChain :: Int
maxCNameChain = 16
