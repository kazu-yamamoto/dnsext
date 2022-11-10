{-# LANGUAGE OverloadedStrings #-}

module RoundTripSpec (spec) where

import Control.Monad
import DNS.SVCB
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode
import Data.ByteString
import Test.Hspec

spec :: Spec
spec = do
    runIO $ runInitIO addResourceDataForSVCB
    describe "encodeRData & decodeRData" $ do
        it "encodes/decodes SVCB RR correctly" $ do
            forM_ testVectors $ \bs -> do
                case decodeRData SVCB bs of
                  Right rd -> encodeRData rd `shouldBe` bs
                  Left  _  -> error "decodeRData"
    describe "encode/decodeRData" $ do
        it "treats port" $
            check vectorPort SPK_Port (SPV_Port 53)
        it "treats IPv6Hint" $
            check vector2IPv6 SPK_IPv6Hint (SPV_IPv6Hint ["2001:db8::1","2001:db8::53:1"])
        it "treats IPv6Hint" $
            check vectorIPv4EmbeddedIPv6 SPK_IPv6Hint (SPV_IPv6Hint ["2001:db8:122:344::192.0.2.33"])
        it "treats mandatory" $
            check vectorArbitrary SPK_Mandatory (SPV_Mandatory [SPK_ALPN,SPK_IPv4Hint])

check :: (SPV a, Show a, Eq a) => ByteString -> SvcParamKey -> a -> IO ()
check vector key value =
    case decodeRData HTTPS vector of
      Left _   -> error "cannot decode HTTPS RR"
      Right rd -> do
          encodeRData rd `shouldBe` vector
          case fromRData rd of
            Nothing -> error "this is not HTTPS RR"
            Just (RD_HTTPS https) -> do
                case lookupSvcParams key $ svcb_params https of
                  Nothing -> error "no such parameter"
                  Just o -> case decodeSvcParamValue o of
                    Nothing -> error "value cannot be decoded"
                    Just v  -> do
                        v `shouldBe` value
                        encodeSvcParamValue v `shouldBe` o

testVectors :: [ByteString]
testVectors = [ vectorAliasMode
              , vectorDot
              , vectorPort
              , vectorGenericKey
              , vectorEscape
              , vector2IPv6
              , vectorIPv4EmbeddedIPv6
              , vectorArbitrary
              , vectorALPN
              ]

-- example.com.   HTTPS   0 foo.example.com.
vectorAliasMode :: ByteString
vectorAliasMode = "\x00\x00\x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00"

-- example.com.   SVCB   1 .
vectorDot :: ByteString
vectorDot = "\x00\x01\x00"

-- example.com.   SVCB   16 foo.example.com. port=53
vectorPort :: ByteString
vectorPort = "\x00\x10\x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x03\x00\x02\x00\x35"

-- example.com.   SVCB   1 foo.example.com. key667=hello
vectorGenericKey :: ByteString
vectorGenericKey = "\x00\x01\x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x02\x9b\x00\x05\x68\x65\x6c\x6c\x6f"

-- example.com.   SVCB   1 foo.example.com. key667="hello\210qoo"
vectorEscape :: ByteString
vectorEscape = "\x00\x01\x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x02\x9b\x00\x09\x68\x65\x6c\x6c\x6f\xd2\x71\x6f\x6f"

-- example.com.   SVCB   1 foo.example.com. (
--                       ipv6hint="2001:db8::1,2001:db8::53:1"
--                       )
vector2IPv6 :: ByteString
vector2IPv6 = "\x00\x01\x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x06\x00\x20\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01"

-- example.com.   SVCB   1 example.com. ipv6hint="2001:db8:122:344::192.0.2.33"
vectorIPv4EmbeddedIPv6 :: ByteString
vectorIPv4EmbeddedIPv6 = "\x00\x01\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x06\x00\x10\x20\x01\x0d\xb8\x01\x22\x03\x44\x00\x00\x00\x00\xc0\x00\x02\x21"

-- example.com.   SVCB   16 foo.example.org. (
--                       alpn=h2,h3-19 mandatory=ipv4hint,alpn
--                       ipv4hint=192.0.2.1
--                       )
vectorArbitrary :: ByteString
vectorArbitrary = "\x00\x10\x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x00\x00\x04\x00\x01\x00\x04\x00\x01\x00\x09\x02\x68\x32\x05\x68\x33\x2d\x31\x39\x00\x04\x00\x04\xc0\x00\x02\x01"

-- example.com.   SVCB   16 foo.example.org. alpn="f\\\\oo\\,bar,h2"
-- example.com.   SVCB   16 foo.example.org. alpn=f\\\092oo\092,bar,h2
vectorALPN :: ByteString
vectorALPN = "\x00\x10\x03\x66\x6f\x6f\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6f\x72\x67\x00\x00\x01\x00\x0c\x08\x66\x5c\x6f\x6f\x2c\x62\x61\x72\x02\x68\x32"
