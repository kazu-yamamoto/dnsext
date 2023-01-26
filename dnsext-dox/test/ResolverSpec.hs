{-# LANGUAGE OverloadedStrings #-}

module ResolverSpec where

import DNS.Types
import DNS.Do53.Internal
import Test.Hspec

import DNS.DoX.Internal


spec :: Spec
spec = describe "solvers" $ do

    let q = Question "www.mew.org" A classIN
    it "resolves well with TLS" $ do
        let ri0 = defaultResolvInfo {
                rinfoHostName      = "1.1.1.1"
              , rinfoPortNumber    = 853
              }

        ans0 <- tlsResolver 32768 ri0 q mempty
        rcode (flags (header ans0)) `shouldBe` NoErr

        let ri1 = defaultResolvInfo {
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 853
              }

        ans1 <- tlsResolver 32768 ri1 q mempty
        rcode (flags (header ans1)) `shouldBe` NoErr

        let ri2 = defaultResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 853
              }

        ans2 <- tlsResolver 32768 ri2 q mempty
        rcode (flags (header ans2)) `shouldBe` NoErr

    it "resolves well with QUIC" $ do
        let ri2 = defaultResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 853
              }

        ans2 <- quicResolver 32768 ri2 q mempty
        rcode (flags (header ans2)) `shouldBe` NoErr

    it "resolves well with HTTP/2" $ do
        let ri0 = defaultResolvInfo {
                rinfoHostName      = "1.1.1.1"
              , rinfoPortNumber    = 443
              }

        ans0 <- http2Resolver 32768 ri0 q mempty
        rcode (flags (header ans0)) `shouldBe` NoErr

        let ri1 = defaultResolvInfo {
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 443
              }

        ans1 <- http2Resolver 32768 ri1 q mempty
        rcode (flags (header ans1)) `shouldBe` NoErr

        let ri2 = defaultResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 443
              }

        ans2 <- http2Resolver 32768 ri2 q mempty
        rcode (flags (header ans2)) `shouldBe` NoErr

    it "resolves well with HTTP/3" $ do
        let ri2 = defaultResolvInfo {
                rinfoHostName      = "94.140.14.140"
              , rinfoPortNumber    = 443
              }

        ans2 <- http3Resolver 32768 ri2 q mempty
        rcode (flags (header ans2)) `shouldBe` NoErr
