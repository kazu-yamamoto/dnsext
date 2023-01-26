{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import DNS.Types
import Test.Hspec

import DNS.Do53.Client
import DNS.Do53.Internal


spec :: Spec
spec = describe "solvers" $ do

    it "resolves well with UDP" $ do
        let q = Question "www.mew.org" A classIN
            ri = defaultResolvInfo {
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 53
              }
            -- Google's resolvers support the AD and CD bits
            qctl = adFlag FlagSet <> ednsEnabled FlagClear

        ans <- udpResolver 1 ri q qctl
        rcode (flags (header ans)) `shouldBe` NoErr

    it "resolves well with TCP" $ do
        let q = Question "www.mew.org" A classIN
            ri = defaultResolvInfo {
                rinfoHostName      = "8.8.8.8"
              , rinfoPortNumber    = 53
              }
            -- Google's resolvers support the AD and CD bits
            qctl = adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet

        ans <- tcpResolver (32 * 1024) ri q qctl
        rcode (flags (header ans)) `shouldBe` NoErr
