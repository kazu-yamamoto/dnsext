module QuerySpec where

import Test.Hspec

import Control.Concurrent (threadDelay)
import qualified DNS.Do53.Memo as Cache
import qualified DNS.SEC as DNS
import DNS.Types (TYPE (A, AAAA, CNAME, MX, NS, PTR, SOA))
import qualified DNS.Types as DNS
import Data.Either (isRight)
import Data.Maybe (isJust, isNothing)
import Data.String (fromString)
import System.Environment (lookupEnv)

import DNS.Cache.Iterative (
    Delegation (..),
    Env (..),
    newEnv,
    replyMessage,
    getResultIterative,
    rootHint,
    runDNSQuery,
 )
import qualified DNS.Cache.Iterative as Iterative
import qualified DNS.Cache.TimeCache as TimeCache

data AnswerResult
    = Empty DNS.RCODE
    | NotEmpty DNS.RCODE
    | Failed
    deriving (Eq, Show)

data VerifyResult
    = Verified
    | NotVerified
    deriving (Eq, Show)

data VAnswerResult
    = VEmpty DNS.RCODE
    | VNotEmpty DNS.RCODE VerifyResult
    | VFailed
    deriving (Eq, Show)

spec :: Spec
spec = do
    let getEnvBool n = runIO $ maybe False ((== "1") . take 1) <$> lookupEnv n
    disableV6NS <- getEnvBool "DISABLE_V6_NS"
    debug <- getEnvBool "QTEST_DEBUG"
    runIO $ DNS.runInitIO DNS.addResourceDataForDNSSEC
    envSpec
    cacheStateSpec disableV6NS
    querySpec disableV6NS debug

envSpec :: Spec
envSpec = describe "env" $ do
    it "rootHint" $ do
        let sp p = case p of Delegation _ _ _ _ -> True -- check not error
        rootHint `shouldSatisfy` sp

cacheStateSpec :: Bool -> Spec
cacheStateSpec disableV6NS = describe "cache-state" $ do
    tcache@(getSec, _) <- runIO TimeCache.new
    let cacheConf = Cache.getDefaultStubConf (2 * 1024 * 1024) 600 getSec
    memo <- runIO $ Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
        getCache = Cache.readMemo memo

    let getResolveCache n ty = do
            cxt <- newEnv (\_ _ _ -> pure ()) disableV6NS (insert, getCache) tcache
            eresult <-
                (snd <$>)
                    <$> Iterative.runResolve cxt (fromString n) ty mempty
            threadDelay $ 1 * 1000 * 1000
            let convert xs =
                    [ ((dom, typ), (crs, rank))
                    | (Cache.Question dom typ _, (_, Cache.Val crs rank)) <- xs
                    ]
            (,) eresult . convert . Cache.dump <$> getCache_ cxt
        clookup cs n typ = lookup (fromString n, typ) cs
        check cs n typ = lookup (fromString n, typ) cs

    it "answer - a" $ do
        (_, cs) <- getResolveCache "iij.ad.jp." A
        fmap snd (clookup cs "iij.ad.jp." A) `shouldSatisfy` (>= Just Cache.RankAnswer)

    it "nodata - ns" $ do
        (_, cs) <- getResolveCache "iij.ad.jp." A
        check cs "ad.jp." NS `shouldSatisfy` isJust

    it "no zone sub-domain - nodata - ns" $ do
        (_, cs) <- getResolveCache "iij.ad.jp." A
        check cs "ad.jp." NS `shouldSatisfy` isJust

    it "no zone sub-domain - soa" $ do
        (_, cs) <- getResolveCache "iij.ad.jp." A
        check cs "jp." SOA `shouldSatisfy` isJust

    it "shared child zone - ns" $ do
        (_, cs) <- getResolveCache "1.1.1.1.in-addr.arpa." PTR
        check cs "arpa." NS `shouldSatisfy` isNothing

querySpec :: Bool -> Bool -> Spec
querySpec disableV6NS debug = describe "query" $ do
    tcache@(getSec, _) <- runIO TimeCache.new
    let cacheConf = Cache.getDefaultStubConf (2 * 1024 * 1024) 600 getSec
    memo <- runIO $ Cache.getMemo cacheConf
    let insert k ttl crset rank = Cache.insertWithExpiresMemo k ttl crset rank memo
        ucache = (insert, Cache.readMemo memo)
        putLines
            | debug = \lv _ xs -> putStr $ unlines [show lv ++ ": " ++ x | x <- xs]
            | otherwise = \_ _ _ -> pure ()
    cxt <- runIO $ newEnv putLines disableV6NS ucache tcache
    cxt4 <- runIO $ newEnv (\_ _ _ -> pure ()) True ucache tcache
    let refreshRoot = runDNSQuery Iterative.refreshRoot cxt mempty
        runIterative ns n = Iterative.runIterative cxt ns (fromString n) mempty
        runJust n ty = Iterative.runResolveExact cxt (fromString n) ty mempty
        runResolve n ty =
            (snd <$>)
                <$> Iterative.runResolve cxt (fromString n) ty mempty
        getReply n ty ident = do
            e <- runDNSQuery (getResultIterative (fromString n) ty) cxt mempty
            return $ replyMessage e ident [DNS.Question (fromString n) ty DNS.classIN]

    let printQueryError :: Show e => Either e a -> IO ()
        printQueryError = either (putStrLn . ("    QueryError: " ++) . show) (const $ pure ())
        _pprResult (msg, (ans, auth)) =
            unlines $
                ("rcode: " ++ show (DNS.rcode $ DNS.flags $ DNS.header msg))
                    : "answer:"
                    : map (("  " ++) . show) ans
                    ++ "authority:"
                    : map (("  " ++) . show) auth

        checkAnswer msg
            | null (DNS.answer msg) = Empty rcode
            | otherwise = NotEmpty rcode
          where
            rcode = DNS.rcode $ DNS.flags $ DNS.header msg
        verified rrsets
            | all Iterative.rrsetVerified rrsets = Verified
            | otherwise = NotVerified
        checkVAnswer (msg, (vans, _))
            | null vans = VEmpty rcode
            | otherwise = VNotEmpty rcode (verified vans)
          where
            rcode = DNS.rcode $ DNS.flags $ DNS.header msg
        checkResult = either (const Failed) (checkAnswer . fst)

    it "root-priming" $ do
        result <- refreshRoot
        printQueryError result
        result `shouldSatisfy` isRight

    root <-
        runIO $
            either (fail . ("root-priming error: " ++) . show) return =<< refreshRoot

    it "iterative" $ do
        result <- runIterative root "iij.ad.jp."
        printQueryError result
        result `shouldSatisfy` isRight

    it "iterative - long" $ do
        result <- runIterative root "c.b.a.pt.dns-oarc.net."
        printQueryError result
        result `shouldSatisfy` isRight

    it "resolve-just - ns" $ do
        result <- runJust "iij.ad.jp." NS
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - a" $ do
        result <- runJust "iij.ad.jp." A
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - aaaa" $ do
        result <- runJust "iij.ad.jp." AAAA
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - mx" $ do
        result <- runJust "iij.ad.jp." MX
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - cname" $ do
        result <- runJust "porttest.dns-oarc.net." CNAME
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - ptr" $ do
        result <- runJust "1.1.1.1.in-addr.arpa." PTR
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - nx" $ do
        result <- runJust "does-not-exist.dns-oarc.net." A
        checkResult result `shouldBe` Empty DNS.NameErr

    it "resolve-just - nx on iterative" $ do
        result <- runJust "media-router-aol1.prod.media.yahoo.com." CNAME
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve-just - delegation with aa" $ do
        -- `dig -4 @ns1.alibabadns.com. danuoyi.alicdn.com. A` has delegation authority section with aa flag
        result <-
            Iterative.runResolveExact
                cxt4
                (fromString "sc02.alicdn.com.danuoyi.alicdn.com.")
                A
                mempty
        printQueryError result
        checkResult result `shouldBe` NotEmpty DNS.NoErr

    it "resolve - cname" $ do
        result <- runResolve "porttest.dns-oarc.net." CNAME
        printQueryError result
        let cached (rcode, rrs, _)
                | null rrs = VEmpty rcode
                | otherwise = VNotEmpty rcode NotVerified
        either (const VFailed) (either cached checkVAnswer) result
            `shouldBe` VNotEmpty DNS.NoErr Verified

    it "resolve - a via cname" $ do
        result <- runResolve "clients4.google.com." A
        printQueryError result
        isRight result `shouldBe` True

    it "resolve - a with DNSSEC_OK" $ do
        result <- runResolve "iij.ad.jp." A
        printQueryError result
        isRight result `shouldBe` True
        let cached (rcode, rrs, _)
                | null rrs = VEmpty rcode
                | otherwise = VNotEmpty rcode NotVerified
        either (const VFailed) (either cached checkVAnswer) result
            `shouldBe` VNotEmpty DNS.NoErr Verified

    it "get-reply - nx via cname" $ do
        result <- getReply "media.yahoo.com." A 0
        either (const Failed) checkAnswer result `shouldBe` NotEmpty DNS.NameErr

    it "get-reply - a accumulated via cname" $ do
        result <- getReply "media-router-aol1.prod.media.yahoo.com." A 0
        either (const 0) (length . DNS.answer) result `shouldSatisfy` (> 1)
