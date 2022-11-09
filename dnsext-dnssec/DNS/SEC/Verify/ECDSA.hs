module DNS.SEC.Verify.ECDSA (
    ecdsaP256SHA
  , ecdsaP384SHA
  ) where

import Control.Monad (unless)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Crypto.Number.Serialize (os2ip)
import Crypto.PubKey.ECC.Types (Curve, CurveName)
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import Crypto.PubKey.ECC.ECDSA (PublicKey, Signature)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.Hash (HashAlgorithm)
import Crypto.Hash.Algorithms (SHA256(..), SHA384(..))

import DNS.Types
import qualified DNS.Types.Opaque as Opaque

import DNS.SEC.PubKey
import DNS.SEC.Verify.Types

{- Verify RRSIG with DNSKEY using Elliptic Curve Digital Signature Algorithm (ECDSA)
-- https://datatracker.ietf.org/doc/html/rfc6605
 -}

ecdsaP256SHA :: RRSIGImpl
ecdsaP256SHA = ecdsaHelper ECC.SEC_p256r1 SHA256

ecdsaP384SHA :: RRSIGImpl
ecdsaP384SHA = ecdsaHelper ECC.SEC_p384r1 SHA384

ecdsaHelper :: HashAlgorithm hash => CurveName -> hash -> RRSIGImpl
ecdsaHelper cn hash =
  RRSIGImpl
  { rrsigIGetKey = ecdsaDecodePubKey cn curve
  , rrsigIGetSig = ecdsaDecodeSignature curve
  , rrsigIVerify = ecdsaVerify hash
  }
  where
    curve = ECC.getCurveByName cn

curveSizeBytes :: Curve -> Int
curveSizeBytes curve = (ECC.curveSizeBits curve + 7) `div` 8

ecdsaDecodePubKey :: CurveName -> Curve -> PubKey -> Either String PublicKey
ecdsaDecodePubKey cn curve (PubKey_ECDSA xs ys) = do
  unless (xlen == size && ylen == size) $
    Left $ "ecdsaDecodePubKey: invalid length of pubkey bytes: " ++
    "expect " ++ show (size, size) ++ " =/= " ++ "actual " ++ show (xlen, ylen)
  unless (ECC.isPointValid curve point) $
    Left $ "ecdsaDecodePubKey: not valid point on curve " ++ show cn
  return $ ECDSA.PublicKey curve point
  where
    size = curveSizeBytes curve
    xlen = Opaque.length xs
    ylen = Opaque.length ys
    point = ECC.Point (os2ip $ Opaque.toByteString xs) (os2ip $ Opaque.toByteString ys)
ecdsaDecodePubKey _  _     _                    =
  Left "ecdsaDecodePubKey: not ECDSA pubkey format"

ecdsaDecodeSignature :: Curve -> Opaque -> Either String Signature
ecdsaDecodeSignature curve ss = do
  unless (slen == size * 2) $
    Left $
    "ecdsaDecodeSignature: invalid length of signature bytes: " ++
    "expect " ++ show (size * 2) ++ ", " ++
    "actual " ++ show slen
  return $ ECDSA.Signature (os2ip rb) (os2ip sb)
  where
    size = curveSizeBytes curve
    slen = Opaque.length ss
    (rb, sb) = BS.splitAt size $ Opaque.toByteString ss

ecdsaVerify :: HashAlgorithm hash => hash -> PublicKey -> Signature -> ByteString -> Either String Bool
ecdsaVerify hash pubkey sig = Right . ECDSA.verify hash pubkey sig
