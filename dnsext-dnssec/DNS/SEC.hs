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
  extendRR DS      "DS"      (\len -> toRData <$> get_ds      len)
  extendRR DNSKEY  "DNSKEY"  (\len -> toRData <$> get_dnskey  len)
  extendRR CDS     "CDS"     (\len -> toRData <$> get_cds     len)
  extendRR CDNSKEY "CDNSKEY" (\len -> toRData <$> get_cdnskey len)
  extendRR RRSIG   "RRSIG"   (\len -> toRData <$> get_rrsig   len)
  extendRR NSEC    "NSEC"    (\len -> toRData <$> get_nsec    len)
  extendRR NSEC3   "NSEC3"   (\len -> toRData <$> get_nsec3   len)
  extendRR NSEC3PARAM "NSEC3PARAM" (\len -> toRData <$> get_nsec3param len)
  extendOpt DAU "DAU" (\len -> toOData <$> get_dau len)
  extendOpt DAU "DHU" (\len -> toOData <$> get_dhu len)
  extendOpt DAU "N3U" (\len -> toOData <$> get_n3u len)
