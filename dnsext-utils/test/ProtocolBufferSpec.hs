{-# LANGUAGE OverloadedStrings #-}

module ProtocolBufferSpec where

import Data.ByteString ()
import Test.Hspec

import DNS.TAP.ProtocolBuffer

spec :: Spec
spec = do
    describe "encode & decode" $ do
        it "can encode then decode" $ do
            roundTrip empty
            roundTrip $ setVAR 1 10000 empty
            roundTrip $ setVAR 1 12345 empty
            roundTrip $ setI32 2 10000 empty
            roundTrip $ setI32 2 12345 empty
            roundTrip $ setI64 3 10000 empty
            roundTrip $ setI64 3 12345 empty
            roundTrip $ setS 4 "foo" empty
            roundTrip $ setS 5 "foobar" $ setVAR 6 12345678 empty

roundTrip :: Object -> Expectation
roundTrip obj = decode (encode obj) `shouldBe` obj
