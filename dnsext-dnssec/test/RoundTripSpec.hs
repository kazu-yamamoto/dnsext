{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TransformListComp #-}

module RoundTripSpec (spec) where

import Control.Monad (replicateM)
import DNS.SEC
import DNS.SEC.Internal
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode
import qualified DNS.Types.Opaque as Opaque
import qualified Data.ByteString as BS
import Data.String (fromString)
import Data.Word
import GHC.Exts (groupWith, the)
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck (Gen, arbitrary, choose, elements, forAll, frequency)

spec :: Spec
spec = do
    runIO $ runInitIO addResourceDataForDNSSEC
    prop "ResourceRecord" . forAll genResourceRecord $ \rr -> do
        let bs = encodeResourceRecord rr
        decodeResourceRecord bs `shouldBe` Right rr
        fmap encodeResourceRecord (decodeResourceRecord bs) `shouldBe` Right bs
    prop "PubKey_RSA - PubKey iso" . forAll genPubKey_RSA $ \pubkey -> do
        let o = fromPubKey pubkey
        toPubKey_RSA o `shouldSatisfy` (== pubkey)
    prop "PubKey_RSA - bin iso" . forAll genPubKey_RSA_bin $ \o -> do
        let pubkey = toPubKey_RSA o
        fromPubKey pubkey `shouldSatisfy` (== o)

genResourceRecord :: Gen ResourceRecord
genResourceRecord =
    frequency
        [ (8, genRR)
        ]
  where
    genRR = do
        dom <- genDomain
        t <- elements [DS, NSEC, NSEC3]
        ResourceRecord dom t IN <$> genTTL <*> mkRData t

mkRData :: TYPE -> Gen RData
mkRData typ =
    case typ of
        DS ->
            rd_ds
                <$> genWord16
                <*> (toPubAlg <$> genWord8)
                <*> (toDigestAlg <$> genWord8)
                <*> genOpaque
        NSEC -> rd_nsec <$> genDomain <*> genNsecTypes
        NSEC3 -> genNSEC3
        _ -> pure . rd_txt $ fromString ("Unhandled type " <> show typ)
  where
    genNSEC3 = do
        (alg, hlen) <- elements [(1, 32), (2, 64)]
        flgs <- toNSEC3flags <$> elements [0, 1]
        iter <- elements [0 .. 100]
        salt <- elements ["", "AB"]
        hash <- Opaque.fromByteString . BS.pack <$> replicateM hlen genWord8
        rd_nsec3 (toHashAlg alg) flgs iter salt hash <$> genNsecTypes
    genNsecTypes = do
        ntypes <- elements [0 .. 15]
        types <- sequence $ replicate ntypes $ toTYPE <$> elements [1 .. 1024]
        return $
            [ the t
            | t <- types
            , then group by
                (fromTYPE t)
              using
                groupWith
            ]

genPubKey_RSA :: Gen PubKey
genPubKey_RSA = pubKey_RSA <$> genBSize <*> genE
  where
    pubKey_RSA bsize e = PubKey_RSA (bsize * 8) e (fromString $ replicate bsize '\xff')
    genBSize = elements [64, 128, 256]
    genE =
        elements ["\x01\x00\x01", fromString $ "\x01" <> replicate 255 '\x00' <> "\x01"]

genPubKey_RSA_bin :: Gen Opaque
genPubKey_RSA_bin =
    frequency
        [ (1, pubKey_RSA_bin1 <$> genBSize <*> genE1)
        , (1, pubKey_RSA_bin2 <$> genBSize <*> genE2)
        ]
  where
    genE1 = estring <$> frequency [(1, pure 1), (1, pure 255), (3, choose (2, 254))]
    genE2 = estring <$> frequency [(1, pure 256), (3, choose (257, 65535))]

    genBSize = elements [64, 128, 256, 512]
    estring len
        | len > 1 = fromString $ "\x01" <> replicate len '\x00' <> "\x01"
        | otherwise = "\x01"

pubKey_RSA_bin1 :: Int -> Opaque -> Opaque
pubKey_RSA_bin1 bsize e =
    Opaque.concat
        [ Opaque.singleton $ fromIntegral $ Opaque.length e
        , e
        , fromString $ replicate bsize '\xff'
        ]

pubKey_RSA_bin2 :: Int -> Opaque -> Opaque
pubKey_RSA_bin2 bsize e =
    Opaque.concat
        [ Opaque.singleton 0
        , Opaque.singleton $ fromIntegral x
        , Opaque.singleton $ fromIntegral y
        , e
        , fromString $ replicate bsize '\xff'
        ]
  where
    (x, y) = Opaque.length e `divMod` 256

genOpaque :: Gen Opaque
genOpaque =
    Opaque.fromByteString
        <$> elements ["", "a", "a.b", "abc", "a.b.c", "a\\.b.c", "\\001.a.b", "\\$.a.b"]

genDomain :: Gen Domain
genDomain =
    elements
        [".", "a.", "a.b.", "abc.", "a.b.c.", "a\\.b.c.", "\\001.a.b.", "\\$.a.b."]

genWord16 :: Gen Word16
genWord16 = arbitrary

genTTL :: Gen TTL
genTTL = Seconds <$> arbitrary

genWord8 :: Gen Word8
genWord8 = arbitrary
