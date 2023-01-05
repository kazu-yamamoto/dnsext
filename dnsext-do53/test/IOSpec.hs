{-# LANGUAGE OverloadedStrings #-}

module IOSpec where

import DNS.Types
import DNS.Types.Decode
import qualified Network.UDP as UDP
import Test.Hspec

import DNS.Do53.Client
import DNS.Do53.Internal

spec :: Spec
spec = describe "send/receive" $ do

    it "resolves well with UDP" $ do
        sock <- UDP.clientSocket "8.8.8.8" "53" True
        -- Google's resolvers support the AD and CD bits
        let qry = encodeQuery 1 (Question "www.mew.org" A classIN) $
                  adFlag FlagSet <> ednsEnabled FlagClear
        UDP.send sock qry
        Right ans <- decode <$> UDP.recv sock
        identifier (header ans) `shouldBe` 1

    it "resolves well with TCP" $ do
        sock <- openTCP "8.8.8.8" 53
        let qry = encodeQuery 1 (Question "www.mew.org" A classIN) $
                  adFlag FlagClear <> cdFlag FlagSet <> doFlag FlagSet
        sendVC (sendTCP sock) qry
        ans <- recvVC (recvTCP sock)
        identifier (header ans) `shouldBe` 1
