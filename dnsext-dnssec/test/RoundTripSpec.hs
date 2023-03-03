{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TransformListComp #-}

module RoundTripSpec (spec) where

import Control.Monad (replicateM)
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode
import qualified DNS.Types.Opaque as Opaque
import qualified Data.ByteString as BS
import Data.String (fromString)
import Data.Word
import GHC.Exts (the, groupWith)
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck (Gen, arbitrary, choose, elements, forAll, frequency)

import DNS.SEC

spec :: Spec
spec = do
    runIO $ runInitIO addResourceDataForDNSSEC
    prop "ResourceRecord" . forAll genResourceRecord $ \ rr -> do
        let bs = encodeResourceRecord rr
        decodeResourceRecord bs `shouldBe` Right rr
        fmap encodeResourceRecord (decodeResourceRecord bs) `shouldBe` Right bs
    prop "PubKey_RSA - PubKey iso" . forAll genPubKey_RSA $ \ pubkey -> do
        let o = fromPubKey pubkey
        toPubKey_RSA o `shouldSatisfy` (== pubkey)
    prop "PubKey_RSA - bin iso" . forAll genPubKey_RSA_bin $ \ o -> do
        let pubkey = toPubKey_RSA o
        fromPubKey pubkey `shouldSatisfy` (== o)

genResourceRecord :: Gen ResourceRecord
genResourceRecord = frequency
    [ (8, genRR)
    ]
  where
    genRR = do
      dom <- genDomain
      t <- elements [DS, NSEC, NSEC3]
      ResourceRecord dom t classIN <$> genTTL <*> mkRData t

mkRData :: TYPE -> Gen RData
mkRData typ =
    case typ of
        DS    -> rd_ds   <$> genWord16 <*> (toPubAlg <$> genWord8) <*> (toDigestAlg <$> genWord8) <*> genOpaque
        NSEC  -> rd_nsec <$> genDomain <*> genNsecTypes
        NSEC3 -> genNSEC3
        _ -> pure . rd_txt $ fromString ("Unhandled type " <> show typ)
  where
    genNSEC3 = do
        (alg, hlen)  <- elements [(1,32),(2,64)]
        flgs <- toNSEC3flags <$> elements [0,1]
        iter <- elements [0..100]
        salt <- elements ["", "AB"]
        hash <- Opaque.fromByteString . BS.pack <$> replicateM hlen genWord8
        rd_nsec3 (toHashAlg alg) flgs iter salt hash <$> genNsecTypes
    genNsecTypes = do
        ntypes <- elements [0..15]
        types <- sequence $ replicate ntypes $ toTYPE <$> elements [1..1024]
        return $ [ the t |
                   t <- types,
                   then group by (fromTYPE t)
                        using groupWith ]

genPubKey_RSA :: Gen PubKey
genPubKey_RSA = pubKey_RSA <$> genBSize <*> genE
  where
    pubKey_RSA bsize e = PubKey_RSA (bsize * 8) e (fromString $ replicate bsize '\xff')
    genBSize = elements [64, 128, 256]
    genE = elements ["\x01\x00\x01", fromString $ "\x01" <> replicate 255 '\x00' <> "\x01"]

genPubKey_RSA_bin :: Gen Opaque
genPubKey_RSA_bin = pubKey_RSA_bin <$> genBSize <*> genE
  where
    pubKey_RSA_bin bsize e
      | elen >= 256  =  Opaque.concat [ Opaque.singleton 0
                                      , Opaque.singleton $ fromIntegral x
                                      , Opaque.singleton $ fromIntegral y
                                      , e
                                      , n
                                      ]
      | otherwise    =  Opaque.concat [ Opaque.singleton $ fromIntegral elen
                                      , e
                                      , n
                                      ]
      where elen = Opaque.length e
            (x,y) = elen `divMod` 256
            n = fromString $ replicate bsize '\xff'

    genBSize = elements [64, 128, 256, 512]
    genE = estring <$> choose (1, 512)
    estring len
      | len > 1    =  fromString $ "\x01" <> replicate len '\x00' <> "\x01"
      | otherwise  =  "\x01"

genOpaque :: Gen Opaque
genOpaque = Opaque.fromByteString <$> elements [ "", "a", "a.b", "abc", "a.b.c", "a\\.b.c", "\\001.a.b", "\\$.a.b" ]

genDomain :: Gen Domain
genDomain = elements [".", "a.", "a.b.", "abc.", "a.b.c.", "a\\.b.c.", "\\001.a.b.", "\\$.a.b."]

genWord16 :: Gen Word16
genWord16 = arbitrary

genTTL :: Gen TTL
genTTL = Seconds <$> arbitrary

genWord8 :: Gen Word8
genWord8 = arbitrary
