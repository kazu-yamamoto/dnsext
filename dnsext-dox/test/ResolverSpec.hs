{-# LANGUAGE OverloadedStrings #-}

module ResolverSpec where

import DNS.Types
import Test.Hspec
import System.Timeout (timeout)

import DNS.DoX.Internal


spec :: Spec
spec = describe "solvers" $ do

    let q = Question "www.mew.org" A classIN
    it "resolves well with TLS" $ do
        let ri0 = ResolvInfo {
                rinfoHostName      = "1.1.1.1"
              , rinfoPortNumber    = 853
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans0 <- tlsResolver ri0 q mempty
        identifier (header ans0) `shouldBe` 1

        let ri1 = ResolvInfo {
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 853
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans1 <- tlsResolver ri1 q mempty
        identifier (header ans1) `shouldBe` 1

        let ri2 = ResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 853
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans2 <- tlsResolver ri2 q mempty
        identifier (header ans2) `shouldBe` 1

    it "resolves well with QUIC" $ do
        let ri2 = ResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 853
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans2 <- quicResolver ri2 q mempty
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/2" $ do
        let ri0 = ResolvInfo {
                rinfoHostName      = "1.1.1.1"
              , rinfoPortNumber    = 443
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans0 <- http2Resolver ri0 q mempty
        identifier (header ans0) `shouldBe` 1

        let ri1 = ResolvInfo {
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 443
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans1 <- http2Resolver ri1 q mempty
        identifier (header ans1) `shouldBe` 1

        let ri2 = ResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 443
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans2 <- http2Resolver ri2 q mempty
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/3" $ do
        let ri2 = ResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 443
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }

        ans2 <- http3Resolver ri2 q mempty
        identifier (header ans2) `shouldBe` 1
