module QuerySpec where

import Test.Hspec

import Control.Concurrent (threadDelay)
import Data.Either (isRight)
import Data.List (uncons)
import Data.String (fromString)
import Network.DNS (TYPE(NS, A, AAAA, MX, CNAME, PTR))
import qualified Network.DNS as DNS
import System.Environment (lookupEnv)

import qualified DNSC.UpdateCache as UCache
import qualified DNSC.TimeCache as TimeCache
import DNSC.Iterative (newContext, runDNSQuery, replyMessage, reply, query, query1, iterative, rootNS)

spec :: Spec
spec = describe "query" $ do
  disableV6NS <- runIO $ maybe False ((== "1") . take 1) <$> lookupEnv "DISABLE_V6_NS"
  (tcache, _quitT) <- runIO TimeCache.new
  (ucache, _quit) <- runIO $ UCache.new (\_ _ -> pure ())
  cxt <- runIO $ newContext (\_ _ -> pure ()) disableV6NS ucache tcache
  let runIterative ns n = runDNSQuery (iterative ns n) cxt
      runQuery1 n ty = runDNSQuery (query1 n ty) cxt
      runQuery n ty = runDNSQuery (query n ty) cxt
      runReply n ty ident = do
        e <- runDNSQuery (reply n ty True) cxt
        return $ replyMessage e ident [DNS.Question (fromString n) ty]

  let printQueryError :: Show e => Either e a -> IO ()
      printQueryError = either (putStrLn . ("    QueryError: " ++) . show) (const $ pure ())

  it "rootNS" $ do
    let sp p = case p of (_,_) -> True  -- check not error
    rootNS `shouldSatisfy` sp

  it "iterative" $ do
    result <- runIterative rootNS "iij.ad.jp."
    printQueryError result
    result `shouldSatisfy` isRight

  it "iterative - long" $ do
    result <- runIterative rootNS "c.b.a.pt.dns-oarc.net."
    printQueryError result
    result `shouldSatisfy` isRight

  it "query1 - ns" $ do
    result <- runQuery1 "iij.ad.jp." NS
    printQueryError result
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - a" $ do
    result <- runQuery1 "iij.ad.jp." A
    printQueryError result
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - aaaa" $ do
    result <- runQuery1 "iij.ad.jp." AAAA
    printQueryError result
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - mx" $ do
    result <- runQuery1 "iij.ad.jp." MX
    printQueryError result
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - cname" $ do
    result <- runQuery1 "porttest.dns-oarc.net." CNAME
    printQueryError result
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - cname with nx" $ do
    result <- runQuery1 "media-router-aol1.prod.media.yahoo.com." CNAME
    printQueryError result
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query - cname" $ do
    result <- runQuery "porttest.dns-oarc.net." CNAME
    printQueryError result
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query - a via cname" $ do
    result <- runQuery "clients4.google.com." A
    printQueryError result
    isRight result `shouldBe` True

  it "reply - ptr - cache" $ do
    m1 <- runReply "5.0.130.210.in-addr.arpa." PTR 0
    threadDelay $ 2 * 1000 * 1000
    m2 <- runReply "5.0.130.210.in-addr.arpa." PTR 0
    let getTTL = fmap (DNS.rrttl . fst) . uncons . DNS.answer
        t1 = maybe (Left "t1: no RR") return . getTTL =<< m1
        t2 = maybe (Left "t2: no RR") return . getTTL =<< m2
    (>) <$> t1 <*> t2 `shouldBe` Right True

  it "reply - a accumulated via cname" $ do
    result <- runReply "media-router-aol1.prod.media.yahoo.com." A 0
    either (const 0) (length . DNS.answer) result `shouldSatisfy` (> 1)
