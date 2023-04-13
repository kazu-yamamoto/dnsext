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
  , RD_SVCB(..)
  , RD_HTTPS(..)
  , get_svcb
  , get_https
  -- * Service parameters
  , SvcParams
  , lookupSvcParam
  , extractSvcParam
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
  , SPV_Mandatory(..)
  , SPV_ALPN(..)
  , ALPN
  , SPV_Port(..)
  , SPV_IPv4Hint(..)
  , SPV_IPv6Hint(..)
  , SPV_Opaque(..)
  ) where

import DNS.Types

import DNS.SVCB.Key
import DNS.SVCB.Params
import DNS.SVCB.SVCB
import DNS.SVCB.Value
