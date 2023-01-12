{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import DNS.Types
import Test.Hspec

import DNS.Do53.Client
import DNS.Do53.Internal

spec :: Spec
spec = describe "send/receive" $ do

    it "resolves well with UDP" $ do
        let q =Question "www.mew.org" A classIN
            -- Google's resolvers support the AD and CD bits
            cs = adFlag FlagSet <> ednsEnabled FlagClear
        ans <- udpResolve ("8.8.8.8",53) (return 1) q 3000000 1 cs getEpochTime
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        let q = Question "www.mew.org" A classIN
            cs = adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet
        ans <- tcpResolve ("8.8.8.8",53) (return 1) q 3000000 1 cs getEpochTime
        identifier (header ans) `shouldBe` 1
