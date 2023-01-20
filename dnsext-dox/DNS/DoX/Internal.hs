module DNS.DoX.Internal (
    ResolvInfo(..)
  , getEpochTime
  , http2Resolver
  , http3Resolver
  , tlsResolver
  , quicResolver
  )  where

import DNS.Do53.Internal
import DNS.DoX.HTTP2
import DNS.DoX.HTTP3
import DNS.DoX.QUIC
import DNS.DoX.TLS
