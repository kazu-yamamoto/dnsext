{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import DNS.Types
import Test.Hspec

import DNS.Do53.Client
import DNS.Do53.Internal

spec :: Spec
spec = describe "send/receive" $ do

    it "resolves well with UDP" $ do
        let di = Do {
                doQuestion      = Question "www.mew.org" A classIN
              , doHostName      = "8.8.8.8"
              , doPortNumber    = 53
              , doTimeout       = 3000000
              , doRetry         = 1
              , doGenId         = return 1
              , doGetTime       = getEpochTime
              -- Google's resolvers support the AD and CD bits
              , doQueryControls = adFlag FlagSet <> ednsEnabled FlagClear
              }

        ans <- udpResolve di
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        let di = Do {
                doQuestion      = Question "www.mew.org" A classIN
              , doHostName      = "8.8.8.8"
              , doPortNumber    = 53
              , doTimeout       = 3000000
              , doRetry         = 1
              , doGenId         = return 1
              , doGetTime       = getEpochTime
              -- Google's resolvers support the AD and CD bits
              , doQueryControls = adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet
              }
        ans <- tcpResolve di
        identifier (header ans) `shouldBe` 1
