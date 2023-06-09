{-# LANGUAGE OverloadedStrings #-}

module DNS.SEC.Verify.RSA (
    rsaSHA1,
    rsaSHA256,
    rsaSHA512,
)
where

-- memory

-- cryptonite

import Crypto.Hash (HashAlgorithm, hashWith)
import Crypto.Hash.Algorithms (SHA1 (..), SHA256 (..), SHA512 (..))
import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.RSA (PublicKey (..))
import Crypto.PubKey.RSA.Prim (ep)
import DNS.SEC.PubKey
import DNS.SEC.Verify.Types
import DNS.Types
import qualified DNS.Types.Opaque as Opaque
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B8

{- Verify RRSIG with DNSKEY using RSA/SHA-x
-- RSA/SHA-1 https://datatracker.ietf.org/doc/html/rfc3110
-- RSA/SHA-2 https://datatracker.ietf.org/doc/html/rfc5702
 -}

rsaSHA1, rsaSHA256, rsaSHA512 :: RRSIGImpl
rsaSHA1 = rsaSHAHelper sha1
rsaSHA256 = rsaSHAHelper sha256
rsaSHA512 = rsaSHAHelper sha512

rsaSHAHelper :: HashAlgorithm hash => (hash, ByteString) -> RRSIGImpl
rsaSHAHelper alg =
    RRSIGImpl
        { rrsigIGetKey = rsaDecodePubKey
        , rrsigIGetSig = rsaDecodeSignature
        , rrsigIVerify = rsaVerify alg
        }

rsaDecodePubKey :: PubKey -> Either String PublicKey
rsaDecodePubKey (PubKey_RSA bitSize ebytes nbytes)
    | byteSize <= 0 =
        Left $ "RSASHA.rsaDecodePubKey: key size must be positive: " ++ show byteSize
    | r /= 0 =
        Left $
            "RSASHA.rsaDecodePubKey: size in bits is not multiple of 8 : bit-size = "
                ++ show bitSize
    | otherwise =
        Right
            PublicKey
                { public_size = byteSize
                , public_n = os2ip $ Opaque.toByteString nbytes
                , public_e = os2ip $ Opaque.toByteString ebytes
                }
  where
    (byteSize, r) = bitSize `quotRem` 8
rsaDecodePubKey _ = Left "RSASHA.rsaDecodePubKey: not RSA pubkey format"

type Signature = Opaque

rsaDecodeSignature :: Opaque -> Either String Signature
rsaDecodeSignature = Right

rsaVerify
    :: HashAlgorithm hash
    => (hash, ByteString)
    -> PublicKey
    -> Signature
    -> ByteString
    -> Either String Bool
rsaVerify (alg, pkcs1) pubkey sig msg = do
    decoded <- unpadPKCS1Prefix $ ep pubkey $ Opaque.toByteString sig
    return $ hashWith' msg == decoded
  where
    unpadPKCS1Prefix :: ByteString -> Either String ByteString
    unpadPKCS1Prefix s0 = do
        s1 <- stripP "\x00\x01" s0
        let s2 = B8.dropWhile (== '\xff') s1
        s3 <- stripP "\x00" s2
        stripP pkcs1 s3
      where
        stripP prefix =
            maybe (Left $ "RSASHA.rsaVerify: expected prefix: " ++ show prefix) Right
                . B8.stripPrefix prefix
    hashWith' :: ByteString -> ByteString
    hashWith' = BA.convert . hashWith alg

{-
-- PKCS for RSA/SHA
-- https://datatracker.ietf.org/doc/html/rfc8017#section-9.2

     SHA-1:       (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H.
     SHA-224:     (0x)30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c || H.
     SHA-256:     (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H.
     SHA-384:     (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H.
     SHA-512:     (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H.
 -}
sha1 :: (SHA1, ByteString)
sha1 = (SHA1, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14")

sha256 :: (SHA256, ByteString)
sha256 =
    ( SHA256
    , "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
    )

sha512 :: (SHA512, ByteString)
sha512 =
    ( SHA512
    , "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
    )
