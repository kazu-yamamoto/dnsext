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
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 53
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }
            -- Google's resolvers support the AD and CD bits
            qctl = adFlag FlagSet <> ednsEnabled FlagClear

        ans <- udpResolver 1 ri q qctl
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        let q = Question "www.mew.org" A classIN
            ri = ResolvInfo {
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 53
              , rinfoTimeout       = timeout 3000000
              , rinfoGenId         = return 1
              , rinfoGetTime       = getEpochTime
              }
            -- Google's resolvers support the AD and CD bits
            qctl = adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet

        ans <- tcpResolver ri q qctl
        identifier (header ans) `shouldBe` 1
