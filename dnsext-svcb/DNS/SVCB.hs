-- | This module provides Service Binding (SVCB) RR and HTTPS RR.
module DNS.SVCB (
  -- * Extension
    addResourceDataForSVCB
  -- ** DNS types
  , TYPE (
    SVCB
  , HTTPS
  )
  -- ** Resource data
  -- *** SVCB RR
  , RD_SVCB
  , rd_svcb
  -- *** HTTPS RR
  , RD_HTTPS
  , rd_https
  -- * Service parameters
  , SvcParams
  , lookupSvcParam
  , extractSvcParam
  , toSvcParams
  -- ** Service parameter keys
  , SvcParamKey (
    SPK_Mandatory
  , SPK_ALPN
  , SPK_NoDefaultALPN
  , SPK_Port
  , SPK_IPv4Hint
  , SPK_ECH
  , SPK_IPv6Hint
  )
  , fromSvcParamKey
  , toSvcParamKey
  -- ** Service parameter values
  , SvcParamValue
  , SPV(..)
  --- *** Mandatory
  , SPV_Mandatory
  , mandatory_keys
  , spv_mandatory
  --- *** ALPN
  , SPV_ALPN
  , alpn_names
  , spv_alpn
  , ALPN
  --- *** Port
  , SPV_Port
  , port_number
  , spv_port
  --- *** IPv4Hint
  , SPV_IPv4Hint
  , hint_ipv4s
  , spv_ipv4hint
  --- *** IPv6Hint
  , SPV_IPv6Hint
  , hint_ipv6s
  , spv_ipv6hint
  --- *** DoHPath
  , SPV_DoHPath
  , dohpath
  , spv_dohpath
  --- *** Others
  , SPV_Opaque
  , opaque_value
  , spv_opaque
  ) where

import DNS.Types

import DNS.SVCB.Key
import DNS.SVCB.Params
import DNS.SVCB.SVCB
import DNS.SVCB.Value
