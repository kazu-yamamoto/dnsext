{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module ResolverSpec where

import DNS.Do53.Internal
import DNS.DoX.Internal
import DNS.Types
import Data.ByteString.Short ()
import Test.Hspec

spec :: Spec
spec = describe "solvers" $ do
    let q = Question "www.mew.org" A classIN
    it "resolves well with TLS" $ do
        let ri0 =
                defaultResolvInfo
                    { rinfoHostName = "1.1.1.1"
                    , rinfoPortNumber = 853
                    }

        Result{..} <- tlsResolver 32768 ri0 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr

        let ri1 =
                defaultResolvInfo
                    { rinfoHostName = "8.8.8.8"
                    , rinfoPortNumber = 853
                    }

        Result{..} <- tlsResolver 32768 ri1 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr

        let ri2 =
                defaultResolvInfo
                    { rinfoHostName = "94.140.14.140"
                    , rinfoPortNumber = 853
                    }

        Result{..} <- tlsResolver 32768 ri2 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr

    it "resolves well with QUIC" $ do
        let ri2 =
                defaultResolvInfo
                    { rinfoHostName = "94.140.14.140"
                    , rinfoPortNumber = 853
                    }

        Result{..} <- quicResolver 32768 ri2 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr

    it "resolves well with HTTP/2" $ do
        let ri0 =
                defaultResolvInfo
                    { rinfoHostName = "1.1.1.1"
                    , rinfoPortNumber = 443
                    }

        Result{..} <- http2Resolver "/dns-query" 32768 ri0 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr

        let ri1 =
                defaultResolvInfo
                    { rinfoHostName = "8.8.8.8"
                    , rinfoPortNumber = 443
                    }

        Result{..} <- http2Resolver "/dns-query" 32768 ri1 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr

        let ri2 =
                defaultResolvInfo
                    { rinfoHostName = "94.140.14.140"
                    , rinfoPortNumber = 443
                    }

        Result{..} <- http2Resolver "/dns-query" 32768 ri2 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr

    it "resolves well with HTTP/3" $ do
        let ri2 =
                defaultResolvInfo
                    { rinfoHostName = "94.140.14.140"
                    , rinfoPortNumber = 443
                    }

        Result{..} <- http3Resolver "/dns-query" 32768 ri2 q mempty
        let Reply{..} = resultReply
        rcode (flags (header replyDNSMessage)) `shouldBe` NoErr
