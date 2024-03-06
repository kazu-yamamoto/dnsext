{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module IOSpec where

import DNS.Do53.Internal
import DNS.Types
import System.Timeout
import Test.Hspec

q :: Question
q = Question "www.mew.org" A IN

google :: ResolveInfo
google =
    defaultResolveInfo
        { rinfoIP = "8.8.8.8"
        }

cloudflare :: ResolveInfo
cloudflare =
    defaultResolveInfo
        { rinfoIP = "1.1.1.1"
        }

bad0 :: ResolveInfo
bad0 =
    defaultResolveInfo
        { rinfoIP = "192.0.2.1"
        , rinfoActions = defaultResolveActions{ractionTimeout = timeout 100000}
        }

bad1 :: ResolveInfo
bad1 =
    defaultResolveInfo
        { rinfoIP = "192.0.2.2"
        , rinfoActions = defaultResolveActions{ractionTimeout = timeout 100000}
        }

spec :: Spec
spec = describe "solvers" $ do
    it "resolves well with UDP" $ do
        r <- udpResolver 1 google q mempty
        checkNoErr r

    it "resolves well with TCP" $ do
        r <- tcpResolver (32 * 1024) google q mempty
        checkNoErr r

    it "resolves well concurrently (0)" $ do
        let resolver = udpResolver 2
            renv = ResolveEnv resolver True [google, cloudflare]
        r <- resolve renv q mempty
        checkNoErr r

    it "resolves well concurrently (1)" $ do
        let resolver = udpResolver 2
            renv = ResolveEnv resolver True [cloudflare, bad0]
        r <- resolve renv q mempty
        checkNoErr r

    it "resolves well concurrently (2)" $ do
        let resolver = udpResolver 1
            renv = ResolveEnv resolver True [bad0, bad1]
        resolve renv q mempty `shouldThrow` dnsException

dnsException :: Selector DNSError
dnsException = const True

checkNoErr :: Result -> Expectation
checkNoErr Result{..} = rcode replyDNSMessage `shouldBe` NoErr
  where
    Reply{..} = resultReply
