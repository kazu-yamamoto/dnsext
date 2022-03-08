module QuerySpec where

import Test.Hspec

import Data.Either (isRight)
import Network.DNS (TYPE(NS, A, AAAA, MX, CNAME, TXT))
import qualified Network.DNS as DNS

import DNSC.Iterative (runQuery, runQuery1, runIterative, rootNS)

spec :: Spec
spec = describe "query" $ do

  it "rootNS" $ do
    let sp p = case p of (_,_) -> True  -- check not error
    rootNS `shouldSatisfy` sp

  it "iterative" $ do
    let domain = "iij.ad.jp."
    result <- runIterative rootNS domain
    result `shouldSatisfy` isRight

  it "iterative - long" $ do
    let domain = "c.b.a.pt.dns-oarc.net."
    result <- runIterative rootNS domain
    result `shouldSatisfy` isRight

  it "query1 - ns" $ do
    result <- runQuery1 "iij.ad.jp." NS
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - a" $ do
    result <- runQuery1 "iij.ad.jp." A
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - aaaa" $ do
    result <- runQuery1 "iij.ad.jp." AAAA
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - mx" $ do
    result <- runQuery1 "iij.ad.jp." MX
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query1 - cname" $ do
    result <- runQuery1 "porttest.dns-oarc.net." CNAME
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)

  it "query - a" $ do
    result <- runQuery "porttest.dns-oarc.net." TXT
    isRight result `shouldBe` True
    let Right msg = result
    length (DNS.answer msg) `shouldSatisfy` (> 0)
