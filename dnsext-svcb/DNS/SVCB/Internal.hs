module DNS.SVCB.Internal (
    get_svcb,
    get_https,
    SvcParamValue (..),
    SPV_Mandatory (..),
    SPV_Port (..),
    SPV_IPv4Hint (..),
    SPV_IPv6Hint (..),
    SPV_ALPN (..),
    SPV_Opaque (..),
    SPV_DoHPath (..),
)
where

import DNS.SVCB.SVCB
import DNS.SVCB.Value
