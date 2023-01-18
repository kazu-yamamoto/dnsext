{-# LANGUAGE OverloadedStrings #-}

module SolverSpec where

import DNS.Types
import Test.Hspec
import System.Timeout (timeout)

import DNS.DoX.Internal


spec :: Spec
spec = describe "solvers" $ do

    it "resolves well with TLS" $ do
        let si0 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "1.1.1.1"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = tlsResolver -- dummy
              }

        ans0 <- tlsResolver si0
        identifier (header ans0) `shouldBe` 1

        let si1 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "8.8.8.8"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = tlsResolver -- dummy
              }

        ans1 <- tlsResolver si1
        identifier (header ans1) `shouldBe` 1

        let si2 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = tlsResolver -- dummy
              }

        ans2 <- tlsResolver si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with QUIC" $ do
        let si2 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = quicResolver -- dummy
              }

        ans2 <- quicResolver si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/2" $ do
        let si0 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "1.1.1.1"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = http2Resolver -- dummy
              }

        ans0 <- http2Resolver si0
        identifier (header ans0) `shouldBe` 1

        let si1 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "8.8.8.8"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = http2Resolver -- dummy
              }

        ans1 <- http2Resolver si1
        identifier (header ans1) `shouldBe` 1

        let si2 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = http2Resolver -- dummy
              }

        ans2 <- http2Resolver si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/3" $ do
        let si2 = ResolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvResolver      = http3Resolver -- dummy
              }

        ans2 <- http3Resolver si2
        identifier (header ans2) `shouldBe` 1
