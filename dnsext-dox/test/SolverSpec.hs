{-# LANGUAGE OverloadedStrings #-}

module SolverSpec where

import DNS.Types
import Test.Hspec
import System.Timeout (timeout)

import DNS.DoX.Internal


spec :: Spec
spec = describe "solvers" $ do

    it "resolves well with TLS" $ do
        let si0 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "1.1.1.1"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = tlsSolver -- dummy
              }

        ans0 <- tlsSolver si0
        identifier (header ans0) `shouldBe` 1

        let si1 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "8.8.8.8"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = tlsSolver -- dummy
              }

        ans1 <- tlsSolver si1
        identifier (header ans1) `shouldBe` 1

        let si2 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = tlsSolver -- dummy
              }

        ans2 <- tlsSolver si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with QUIC" $ do
        let si2 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 853
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = quicSolver -- dummy
              }

        ans2 <- quicSolver si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/2" $ do
        let si0 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "1.1.1.1"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = http2Solver -- dummy
              }

        ans0 <- http2Solver si0
        identifier (header ans0) `shouldBe` 1

        let si1 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "8.8.8.8"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = http2Solver -- dummy
              }

        ans1 <- http2Solver si1
        identifier (header ans1) `shouldBe` 1

        let si2 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = http2Solver -- dummy
              }

        ans2 <- http2Solver si2
        identifier (header ans2) `shouldBe` 1

    it "resolves well with HTTP/3" $ do
        let si2 = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "94.140.14.140"
              , solvPortNumber    = 443
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              , solvQueryControls = mempty
              , solvSolver        = http3Solver -- dummy
              }

        ans2 <- http3Solver si2
        identifier (header ans2) `shouldBe` 1
