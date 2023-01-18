{-# LANGUAGE OverloadedStrings #-}

module SolverSpec where

import DNS.Types
import Test.Hspec
import System.Timeout (timeout)

import DNS.DoX.Internal


spec :: Spec
spec = describe "solvers" $ do

    let q = Question "www.mew.org" A classIN
    it "resolves well with TLS" $ do
        let si0 = ResolvInfo {
                solvHostName      = "1.1.1.1"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans0 <- tlsResolver q si0
        identifier (header ans0) `shouldBe` 1

        let si1 = ResolvInfo {
                solvHostName      = "8.8.8.8"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans1 <- tlsResolver q si1
        identifier (header ans1) `shouldBe` 1

        let si2 = ResolvInfo {
                solvHostName      = "94.140.14.140"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans2 <- tlsResolver q si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with QUIC" $ do
        let si2 = ResolvInfo {
                solvHostName      = "94.140.14.140"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans2 <- quicResolver q si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/2" $ do
        let si0 = ResolvInfo {
                solvHostName      = "1.1.1.1"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans0 <- http2Resolver q si0
        identifier (header ans0) `shouldBe` 1

        let si1 = ResolvInfo {
                solvHostName      = "8.8.8.8"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans1 <- http2Resolver q si1
        identifier (header ans1) `shouldBe` 1

        let si2 = ResolvInfo {
                solvHostName      = "94.140.14.140"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans2 <- http2Resolver q si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/3" $ do
        let si2 = ResolvInfo {
                solvHostName      = "94.140.14.140"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              }

        ans2 <- http3Resolver q si2
        identifier (header ans2) `shouldBe` 1
