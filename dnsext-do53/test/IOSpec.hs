{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import DNS.Types
import Test.Hspec
import System.Timeout (timeout)

import DNS.Do53.Client
import DNS.Do53.Internal


spec :: Spec
spec = describe "solvers" $ do

    it "resolves well with UDP" $ do
        let si = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "8.8.8.8"
              , solvPortNumber    = 53
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              -- Google's resolvers support the AD and CD bits
              , solvQueryControls = adFlag FlagSet <> ednsEnabled FlagClear
              , solvSolver        = udpSolver -- dummy
              }

        ans <- udpSolver si
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        let si = SolvInfo {
                solvQuestion      = Question "www.mew.org" A classIN
              , solvHostName      = "8.8.8.8"
              , solvPortNumber    = 53
              , solvTimeout       = timeout 3000000
              , solvRetry         = 1
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              -- Google's resolvers support the AD and CD bits
              , solvQueryControls = adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet
              , solvSolver        = tcpSolver -- dummy
              }
        ans <- tcpSolver si
        identifier (header ans) `shouldBe` 1
