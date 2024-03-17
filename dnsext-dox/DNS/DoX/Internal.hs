module DNS.DoX.Internal (
    http2Resolver,
    withHttp2Resolver,
    http2cResolver,
    withHttp2cResolver,
    http3Resolver,
    withHttp3Resolver,
    tlsResolver,
    withTlsResolver,
    quicResolver,
    withQuicResolver,
)
where

import DNS.DoX.HTTP2
import DNS.DoX.HTTP3
import DNS.DoX.QUIC
import DNS.DoX.TLS
