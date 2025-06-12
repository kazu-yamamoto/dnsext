module DNS.DoX.SAN (makeOnServerCertificate) where

import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.BinaryEncoding.Raw (ASN1Class (..))
import Data.ASN1.Encoding (decodeASN1)
import Data.ASN1.Prim (ASN1 (..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Data.IP (IP (..))
import qualified Data.IP as IP
import Data.Maybe (catMaybes)
import Data.Word (Word8)
import Data.X509 (
    Certificate (..),
    ExtensionRaw (..),
    Extensions (..),
    getCertificate,
 )
import Data.X509.Validation (FailedReason (..), validateDefault)
import Network.TLS (CertificateChain (..), OnServerCertificate)

makeOnServerCertificate :: Maybe IP -> OnServerCertificate
makeOnServerCertificate Nothing = validateDefault
makeOnServerCertificate (Just ip) = f
  where
    f caStore validCache sid cc
        | ip `elem` ips = validateDefault caStore validCache sid cc
        | otherwise = return [InvalidName $ show ip ++ " is not included in " ++ show ips]
      where
        ips = getSAN cc

oidSAN :: [Integer]
oidSAN = [2, 5, 29, 17]

getSAN :: CertificateChain -> [IP]
getSAN (CertificateChain []) = []
getSAN (CertificateChain (cert : _)) = case sans of
    [] -> []
    san : _ -> case decodeSAN san of
        Left _ -> []
        Right asn1s -> catMaybes $ map toIPAddr $ asn1s
  where
    exts = case certExtensions $ getCertificate cert of
        Extensions (Just es) -> es
        _ -> []
    sans = filter (\x -> extRawOID x == oidSAN) exts
    decodeSAN = decodeASN1 DER . BL.fromStrict . extRawContent

toIPAddr :: ASN1 -> Maybe IP
toIPAddr (Other Context 7 x) = Just $ toIP $ BS.unpack $ x
toIPAddr _ = Nothing

toIP :: [Word8] -> IP
toIP ws
    | len == 4 = IPv4 $ IP.toIPv4 is
    | len == 16 = IPv6 $ IP.toIPv6b is
    | otherwise = error "toIP"
  where
    len = length ws
    is = map fromIntegral ws
