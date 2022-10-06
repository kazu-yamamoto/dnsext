{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TransformListComp #-}

module RoundTripSpec (spec) where

import Control.Monad (replicateM)
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Word
import GHC.Exts (the, groupWith)
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck (Gen, arbitrary, elements, forAll, frequency)

import DNS.SEC

spec :: Spec
spec = do
    prop "ResourceRecord" . forAll genResourceRecord $ \ rr -> do
        let bs = encodeResourceRecord rr
        decodeResourceRecord' bs `shouldBe` Right rr
        fmap encodeResourceRecord (decodeResourceRecord' bs) `shouldBe` Right bs

genResourceRecord :: Gen ResourceRecord
genResourceRecord = frequency
    [ (8, genRR)
    ]
  where
    genRR = do
      dom <- genDomain
      t <- elements [DS, NSEC, NSEC3]
      ResourceRecord dom t classIN <$> genWord32 <*> mkRData t

mkRData :: TYPE -> Gen RData
mkRData typ =
    case typ of
        DS    -> rd_ds   <$> genWord16 <*> genWord8 <*> genWord8 <*> genOpaque
        NSEC  -> rd_nsec <$> genDomain <*> genNsecTypes
        NSEC3 -> genNSEC3
        _ -> pure . rd_txt $ byteStringToOpaque ("Unhandled type " <> C8.pack (show typ))
  where
    genNSEC3 = do
        (alg, hlen)  <- elements [(1,32),(2,64)]
        flgs <- elements [0,1]
        iter <- elements [0..100]
        salt <- elements ["", "AB"]
        hash <- byteStringToOpaque . BS.pack <$> replicateM hlen genWord8
        rd_nsec3 alg flgs iter salt hash <$> genNsecTypes
    genNsecTypes = do
        ntypes <- elements [0..15]
        types <- sequence $ replicate ntypes $ toTYPE <$> elements [1..1024]
        return $ [ the t |
                   t <- types,
                   then group by (fromTYPE t)
                        using groupWith ]

genOpaque :: Gen Opaque
genOpaque = byteStringToOpaque <$> elements [ "", "a", "a.b", "abc", "a.b.c", "a\\.b.c", "\\001.a.b", "\\$.a.b" ]

genDomain :: Gen Domain
genDomain = shortByteStringToDomain . (<> ".") <$>  genDomainString
  where
    genDomainString = elements
        ["", "a", "a.b", "abc", "a.b.c", "a\\.b.c", "\\001.a.b", "\\$.a.b"]

genWord16 :: Gen Word16
genWord16 = arbitrary

genWord32 :: Gen Word32
genWord32 = arbitrary

genWord8 :: Gen Word8
genWord8 = arbitrary

decodeResourceRecord' :: ByteString -> Either DNSError ResourceRecord
decodeResourceRecord' = decodeResourceRecord dict
  where
    dict = addResourceDataForDNSSEC defaultDecodeDict
