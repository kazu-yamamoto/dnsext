

module DNS.Cache.RootTrustAnchors (
  rootSepDS
  ) where

import Data.String (fromString)
import qualified DNS.Types.Opaque as Opaque
import DNS.SEC

{- import trust-anchor DS RData from
   https://data.iana.org/root-anchors/root-anchors.xml -}
rootSepDS :: RD_DS
rootSepDS = RD_DS 20326 (PubAlg 8) (DigestAlg 2) digest
  where
    digest =
      either (error . ("rootSepDS: bad configuration: " ++)) id
      $ Opaque.fromBase16
      $ fromString "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
