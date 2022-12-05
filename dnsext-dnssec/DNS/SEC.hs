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
import DNS.SEC.PubAlg
import DNS.SEC.PubKey
import DNS.SEC.Time
import DNS.SEC.Types
import DNS.SEC.Opts

----------------------------------------------------------------

addResourceDataForDNSSEC :: InitIO ()
addResourceDataForDNSSEC = do
  extendRR DS      "DS"      (\len -> toRData <$> getRD_DS      len)
  extendRR DNSKEY  "DNSKEY"  (\len -> toRData <$> getRD_DNSKEY  len)
  extendRR CDS     "CDS"     (\len -> toRData <$> getRD_CDS     len)
  extendRR CDNSKEY "CDNSKEY" (\len -> toRData <$> getRD_CDNSKEY len)
  extendRR RRSIG   "RRSIG"   (\len -> toRData <$> getRD_RRSIG   len)
  extendRR NSEC    "NSEC"    (\len -> toRData <$> getRD_NSEC    len)
  extendRR NSEC3   "NSEC3"   (\len -> toRData <$> getRD_NSEC3   len)
  extendRR NSEC3PARAM "NSEC3PARAM" (\len -> toRData <$> getRD_NSEC3PARAM len)
  extendOpt DAU "DAU" (\len -> toOData <$> decodeOD_DAU len)
  extendOpt DAU "DHU" (\len -> toOData <$> decodeOD_DHU len)
  extendOpt DAU "N3U" (\len -> toOData <$> decodeOD_N3U len)
