module DNS.DoX.SAN (makeOnServerCertificate) where

import qualified Data.ByteString as BS
import Data.IP (IP (..))
import qualified Data.IP as IP
import Data.Maybe (catMaybes)
import Data.X509 (
    AltName (..),
    Certificate (..),
    ExtSubjectAltName (..),
    certExtensions,
    extensionGet,
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

getSAN :: CertificateChain -> [IP]
getSAN (CertificateChain []) = []
getSAN (CertificateChain (cert : _)) = getNames $ getCertificate cert

getNames :: Certificate -> [IP]
getNames cert = maybe [] toAltName $ extensionGet $ certExtensions cert
  where
    toAltName (ExtSubjectAltName names) = catMaybes $ map unAltName names
    unAltName (AltNameIP s) = toIP s
    unAltName _ = Nothing

toIP :: BS.ByteString -> Maybe IP
toIP bs
    | len == 4 = Just $ IPv4 $ IP.toIPv4 is
    | len == 16 = Just $ IPv6 $ IP.toIPv6b is
    | otherwise = Nothing
  where
    ws = BS.unpack bs
    len = length ws
    is = map fromIntegral ws
