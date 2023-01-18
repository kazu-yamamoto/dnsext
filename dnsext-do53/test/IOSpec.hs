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
        let q = Question "www.mew.org" A classIN
            ri = ResolvInfo {
                solvHostName      = "8.8.8.8"
              , solvPortNumber    = 53
              , solvTimeout       = timeout 3000000
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              -- Google's resolvers support the AD and CD bits
              , solvQueryControls = adFlag FlagSet <> ednsEnabled FlagClear
              }

        ans <- udpResolver 1 q ri
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        let q = Question "www.mew.org" A classIN
            ri = ResolvInfo {
                solvHostName      = "8.8.8.8"
              , solvPortNumber    = 53
              , solvTimeout       = timeout 3000000
              , solvGenId         = return 1
              , solvGetTime       = getEpochTime
              -- Google's resolvers support the AD and CD bits
              , solvQueryControls = adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet
              }
        ans <- tcpResolver q ri
        identifier (header ans) `shouldBe` 1
