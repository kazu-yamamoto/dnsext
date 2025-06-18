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
        | any (isTrusted ip) defaultTrusted = return []
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

-- RFC9462 4.3. Opportunistic Discovery
-- private IP addresses [RFC1918], Unique Local Addresses (ULAs) [RFC4193],
-- and Link-Local addresses [RFC3927] [RFC4291] cannot be safely confirmed
-- using TLS certificates under most conditions.
defaultTrusted :: [IP.IPRange]
defaultTrusted = map read
    [ "127.0.0.0/8"
    , "10.0.0.0/8"
    , "169.254.0.0/16"
    , "172.16.0.0/12"
    , "192.168.0.0/16"
    , "::1/128"
    , "fc00::/7"
    , "fe80::/10"
    ]

isTrusted :: IP -> IP.IPRange -> Bool
isTrusted (IPv4 ip) (IP.IPv4Range r) = ip `IP.isMatchedTo` r
isTrusted (IPv6 ip) (IP.IPv6Range r) = ip `IP.isMatchedTo` r
isTrusted (IPv4 ip) (IP.IPv6Range r) = IP.ipv4ToIPv6 ip `IP.isMatchedTo` r
isTrusted _ _ = False
