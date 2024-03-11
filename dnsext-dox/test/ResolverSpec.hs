{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module ResolverSpec where

import Control.Monad
import DNS.Do53.Internal
import DNS.DoX.Internal
import DNS.Types
import Data.ByteString.Short ()
import Test.Hspec

spec :: Spec
spec = describe "solvers" $ do
    let q = Question "www.mew.org" A IN
    it "resolves well with TLS" $ do
        let ri0 =
                defaultResolveInfo
                    { rinfoIP = "1.1.1.1"
                    , rinfoPort = 853
                    }

        Right Result{..} <- tlsResolver ri0 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

        let ri1 =
                defaultResolveInfo
                    { rinfoIP = "8.8.8.8"
                    , rinfoPort = 853
                    }

        Right Result{..} <- tlsResolver ri1 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

        let ri2 =
                defaultResolveInfo
                    { rinfoIP = "94.140.14.140"
                    , rinfoPort = 853
                    }

        Right Result{..} <- tlsResolver ri2 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

        let ri3 =
                defaultResolveInfo
                    { rinfoIP = "103.2.57.5"
                    , rinfoPort = 853
                    }

        Right Result{..} <- tlsResolver ri3 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldSatisfy` (\rc -> rc == NoErr || rc == Refused) -- IIJ public DNS refuses GitHub?
        when (rcode replyDNSMessage == Refused) $ putStrLn $ "    NOTICE: receive Refused from " ++ show (rinfoIP ri3)

    it "resolves well with QUIC" $ do
        let ri2 =
                defaultResolveInfo
                    { rinfoIP = "94.140.14.140"
                    , rinfoPort = 853
                    }

        Right Result{..} <- quicResolver ri2 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

    it "resolves well with HTTP/2" $ do
        let ri0 =
                defaultResolveInfo
                    { rinfoIP = "1.1.1.1"
                    , rinfoPort = 443
                    }

        Right Result{..} <- http2Resolver "/dns-query" ri0 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

        let ri1 =
                defaultResolveInfo
                    { rinfoIP = "8.8.8.8"
                    , rinfoPort = 443
                    }

        Right Result{..} <- http2Resolver "/dns-query" ri1 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

        let ri2 =
                defaultResolveInfo
                    { rinfoIP = "94.140.14.140"
                    , rinfoPort = 443
                    }

        Right Result{..} <- http2Resolver "/dns-query" ri2 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

        let ri3 =
                defaultResolveInfo
                    { rinfoIP = "103.2.57.5"
                    , rinfoPort = 443
                    }

        Right Result{..} <- http2Resolver "/dns-query" ri3 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr

    it "resolves well with HTTP/3" $ do
        let ri2 =
                defaultResolveInfo
                    { rinfoIP = "94.140.14.140"
                    , rinfoPort = 443
                    }

        Right Result{..} <- http3Resolver "/dns-query" ri2 q mempty
        let Reply{..} = resultReply
        rcode replyDNSMessage `shouldBe` NoErr
