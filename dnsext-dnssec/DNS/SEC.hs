module DNS.SEC (
    addResourceDataForDNSSEC
  , module DNS.SEC.Types
  , module DNS.SEC.Opts
  , module DNS.SEC.Time
  , module DNS.SEC.PubAlg
  , module DNS.SEC.PubKey
  , module DNS.SEC.HashAlg
  , module DNS.SEC.Flags
  ) where

import DNS.Types
import DNS.Types.Internal

import DNS.SEC.Flags
import DNS.SEC.HashAlg
import DNS.SEC.Imports
import DNS.SEC.PubAlg
import DNS.SEC.PubKey
import DNS.SEC.Time
import DNS.SEC.Types
import DNS.SEC.Opts

----------------------------------------------------------------

addResourceDataForDNSSEC :: InitIO ()
addResourceDataForDNSSEC = do
  extendRR DS      "DS"      (Proxy :: Proxy RD_DS)
  extendRR DNSKEY  "DNSKEY"  (Proxy :: Proxy RD_DNSKEY)
  extendRR CDS     "CDS"     (Proxy :: Proxy RD_CDS)
  extendRR CDNSKEY "CDNSKEY" (Proxy :: Proxy RD_CDNSKEY)
  extendRR RRSIG   "RRSIG"   (Proxy :: Proxy RD_RRSIG)
  extendRR NSEC    "NSEC"    (Proxy :: Proxy RD_NSEC)
  extendRR NSEC3   "NSEC3"   (Proxy :: Proxy RD_NSEC3)
  extendRR NSEC3PARAM "NSEC3PARAM" (Proxy :: Proxy RD_NSEC3PARAM)
  extendOpt DAU "DAU" (Proxy :: Proxy OD_DAU)
  extendOpt DAU "DHU" (Proxy :: Proxy OD_DHU)
  extendOpt DAU "N3U" (Proxy :: Proxy OD_N3U)
