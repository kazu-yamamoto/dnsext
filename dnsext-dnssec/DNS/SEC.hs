module DNS.SEC (
    addResourceDataForDNSSEC
  -- * Resource data
  -- ** Types
  , TYPE (
    RRSIG
  , DS
  , NSEC
  , DNSKEY
  , NSEC3
  , NSEC3PARAM
  , CDS
  , CDNSKEY
  )
  -- ** DNSEC resource data
  -- *** RRSIG RR
  , RD_RRSIG(..)
  , rd_rrsig
  -- *** DS RR
  , RD_DS(..)
  , rd_ds
  -- *** NSEC RR
  , RD_NSEC(..)
  , rd_nsec
  -- *** DNSKEY RR
  , RD_DNSKEY(..)
  , rd_dnskey
  -- *** NSEC3 RR
  , RD_NSEC3(..)
  , rd_nsec3
  -- *** NSEC3PARAM RR
  , RD_NSEC3PARAM(..)
  , rd_nsec3param
  -- *** CDS RR
  , RD_CDS(..)
  , rd_cds
  -- *** CDNSKEY RR
  , RD_CDNSKEY(..)
  , rd_cdnskey
  -- * Optional
  -- ** Optional code
  , OptCode (
    DAU
  , DHU
  , N3U
  )
  -- ** Optional data
  -- *** DAU
  , OD_DAU(..)
  , od_dau
  -- *** DHU
  , OD_DHU(..)
  , od_dhu
  -- *** N3U
  , OD_N3U(..)
  , od_n3u
    -- * Public key algorithms
  , PubAlg(
    DELETE
  , RSAMD5
  , DH
  , DSA
  , RSASHA1
  , DSA_NSEC3_SHA1
  , RSASHA1_NSEC3_SHA1
  , RSASHA256
  , RSASHA512
  , ECC_GOST
  , ECDSAP256SHA256
  , ECDSAP384SHA384
  , ED25519
  , ED448
  , INDIRECT
  , PRIVATEDNS
  , PRIVATEOID
  )
  , fromPubAlg
  , toPubAlg
    -- * Public keys
  , PubKey(..)
  , toPubKey
  , fromPubKey
    -- * Digest algorithms
  , DigestAlg(
    SHA1
  , SHA256
  , GOST
  , SHA384
  )
  , fromDigestAlg
  , toDigestAlg
    -- * Hash algorithms
  , HashAlg(
    Hash_SHA1
  )
  , fromHashAlg
  , toHashAlg
    -- * Flags
  , DNSKEY_Flag(..)
  , fromDNSKEYflags
  , toDNSKEYflags
  , NSEC3_Flag(..)
  , fromNSEC3flags
  , toNSEC3flags
    -- * DNS time
  , DNSTime
  , fromDNSTime
  , toDNSTime
  , dnsTime
  ) where

import DNS.Types
import DNS.Types.Internal

import DNS.SEC.Flags
import DNS.SEC.HashAlg
import DNS.SEC.Opts
import DNS.SEC.PubAlg
import DNS.SEC.PubKey
import DNS.SEC.Time
import DNS.SEC.Types

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
