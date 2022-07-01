module QuerySpec where

import Test.Hspec

import Control.Concurrent (forkIO, threadDelay)
import Data.Either (isRight)
import Data.List (uncons)
import Data.String (fromString)
import Network.DNS (TYPE(NS, A, AAAA, MX, CNAME, PTR))
import qualified Network.DNS as DNS
import System.Environment (lookupEnv)

import qualified DNSC.UpdateCache as UCache
import qualified DNSC.TimeCache as TimeCache
import DNSC.Iterative (newContext, runDNSQuery, replyMessage, replyResult, rootNS)
import qualified DNSC.Iterative as Iterative

data AnswerResult
  = Empty    DNS.RCODE
  | NotEmpty DNS.RCODE
  | Failed
  deriving (Eq, Show)

spec :: Spec
spec = do
  disableV6NS <- runIO $ maybe False ((== "1") . take 1) <$> lookupEnv "DISABLE_V6_NS"
  envSpec
  querySpec disableV6NS

envSpec :: Spec
envSpec = describe "env" $ do
  it "rootNS" $ do
    let sp p = case p of (_,_) -> True  -- check not error
    rootNS `shouldSatisfy` sp

querySpec :: Bool -> Spec
querySpec disableV6NS = describe "query" $ do
  tcache <- runIO TimeCache.new
  (loops, ucache, _) <- runIO $ UCache.new (\_ _ -> pure ()) tcache $ 2 * 1024 * 1024
  runIO $ mapM_ forkIO loops
  cxt <- runIO $ newContext (\_ _ -> pure ()) disableV6NS ucache tcache
  cxt4 <- runIO $ newContext (\_ _ -> pure ()) True ucache tcache
  let runIterative = Iterative.runIterative cxt
      runJust = Iterative.runResolveJust cxt
      runResolve n ty = (snd  <$>) <$> Iterative.runResolve cxt n ty
      getReply n ty ident = do
        e <- runDNSQuery (replyResult n ty) cxt
        return $ replyMessage e ident [DNS.Question (fromString n) ty]

  let printQueryError :: Show e => Either e a -> IO ()
      printQueryError = either (putStrLn . ("    QueryError: " ++) . show) (const $ pure ())

      checkAnswer msg
        | null (DNS.answer msg)  =  Empty    rcode
        | otherwise              =  NotEmpty rcode
        where rcode = DNS.rcode $ DNS.flags $ DNS.header msg
      checkResult = either (const Failed) (checkAnswer . fst)

  it "iterative" $ do
    result <- runIterative rootNS "iij.ad.jp."
    printQueryError result
    result `shouldSatisfy` isRight

  it "iterative - long" $ do
    result <- runIterative rootNS "c.b.a.pt.dns-oarc.net."
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

  it "resolve-just - nx" $ do
    result <- runJust "does-not-exist.dns-oarc.net." A
    checkResult result `shouldBe` Empty DNS.NameErr

  it "resolve-just - nx on iterative" $ do
    result <- runJust "media-router-aol1.prod.media.yahoo.com." CNAME
    printQueryError result
    checkResult result `shouldBe` NotEmpty DNS.NoErr

  it "resolve-just - delegation with aa" $ do
    -- `dig -4 @ns1.alibabadns.com. danuoyi.alicdn.com. A` has delegation authority section with aa flag
    result <- Iterative.runResolveJust cxt4 "sc02.alicdn.com.danuoyi.alicdn.com." A
    printQueryError result
    checkResult result `shouldBe` NotEmpty DNS.NoErr

  it "resolve - cname" $ do
    result <- runResolve "porttest.dns-oarc.net." CNAME
    printQueryError result
    let cached (rcode, rrs, _)
          | null rrs   =  Empty rcode
          | otherwise  =  NotEmpty rcode
    either (const Failed) (either cached checkAnswer) result `shouldBe` NotEmpty DNS.NoErr

  it "resolve - a via cname" $ do
    result <- runResolve "clients4.google.com." A
    printQueryError result
    isRight result `shouldBe` True

  it "resolve - ptr - cache" $ do
    let handleDNS n = either (fail . (n ++) . show) return
    r1 <- handleDNS "resolve: r1: " =<< runResolve "5.0.130.210.in-addr.arpa." PTR
    threadDelay $ 2 * 1000 * 1000
    r2 <- handleDNS "resolve: r2: " =<< runResolve "5.0.130.210.in-addr.arpa." PTR
    let getRRsTTL n = maybe (fail $ "getTTL: " ++ n ++ ": no RR") return . fmap (DNS.rrttl . fst) . uncons
    t1 <- either (const $ fail "r1: expect not cached result") (getRRsTTL "r1" . DNS.answer) r1
    t2 <- either (\(_, rrs, _) -> getRRsTTL "r2" rrs) (const $ fail "r2: expect cached result") r2
    t1 > t2 `shouldBe` True

  it "get-reply - nx via cname" $ do
    result <- getReply "media.yahoo.com." A 0
    either (const Failed) checkAnswer result `shouldBe` NotEmpty DNS.NameErr

  it "get-reply - a accumulated via cname" $ do
    result <- getReply "media-router-aol1.prod.media.yahoo.com." A 0
    either (const 0) (length . DNS.answer) result `shouldSatisfy` (> 1)
