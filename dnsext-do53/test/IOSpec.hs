{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module IOSpec where

import Control.Exception
import DNS.Do53.Internal
import DNS.Types
import Data.List.NonEmpty (NonEmpty (..))
import Test.Hspec

q :: Question
q = Question "www.mew.org" A IN

google :: ResolveInfo
google =
    defaultResolveInfo
        { rinfoIP = "8.8.8.8"
        , rinfoUDPRetry = 1
        , rinfoVCLimit = 8 * 1024
        }

cloudflare :: ResolveInfo
cloudflare =
    defaultResolveInfo
        { rinfoIP = "1.1.1.1"
        , rinfoUDPRetry = 1
        , rinfoVCLimit = 8 * 1024
        }

bad0 :: ResolveInfo
bad0 =
    defaultResolveInfo
        { rinfoIP = "192.0.2.1"
        , rinfoActions = defaultResolveActions{ractionTimeoutTime = 100000}
        , rinfoUDPRetry = 1
        , rinfoVCLimit = 8 * 1024
        }

bad1 :: ResolveInfo
bad1 =
    defaultResolveInfo
        { rinfoIP = "192.0.2.2"
        , rinfoActions = defaultResolveActions{ractionTimeoutTime = 100000}
        , rinfoUDPRetry = 1
        , rinfoVCLimit = 8 * 1024
        }

spec :: Spec
spec = describe "solvers" $ do
    it "resolves well with UDP" $ do
        r <- udpResolver google q mempty
        checkNoErr r

    it "resolves well with TCP" $ do
        r <- tcpResolver google q mempty
        checkNoErr r

    it "resolves well concurrently (0)" $ do
        let resolver = udpResolver
            renv = ResolveEnv resolver True $ google :| [cloudflare]
        r <- resolve renv q mempty
        checkNoErr r

    it "resolves well concurrently (1)" $ do
        let resolver = udpResolver
            renv = ResolveEnv resolver True $ cloudflare :| [bad0]
        r <- resolve renv q mempty
        checkNoErr r

    it "resolves well concurrently (2)" $ do
        let resolver = udpResolver
            renv = ResolveEnv resolver True $ bad0 :| [bad1]
        resolve renv q mempty `shouldReturn` Left RetryLimitExceeded

dnsException :: Selector DNSError
dnsException = const True

checkNoErr :: Either DNSError Result -> Expectation
checkNoErr (Left e) = throwIO e
checkNoErr (Right Result{..}) = rcode replyDNSMessage `shouldBe` NoErr
  where
    Reply{..} = resultReply
