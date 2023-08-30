{-# LANGUAGE OverloadedStrings #-}

module ProtocolBufferSpec where

import Test.Hspec

import DNS.TAP.ProtocolBuffer

spec :: Spec
spec = do
    describe "encode & decode" $ do
        it "can encode and decode" $ do
            decode (encode empty) `shouldBe` empty


