module DNS.Cache.Server (
    UdpServerConfig (..),
    udpServer,
    VcServerConfig (..),
    tcpServer,
    http2cServer,
    http2Server,
    http3Server,
    tlsServer,
    quicServer,
    Status,
    Server,
    Env,
    HostName,
    PortNumber,
) where

import DNS.Cache.Server.HTTP2
import DNS.Cache.Server.HTTP3
import DNS.Cache.Server.QUIC
import DNS.Cache.Server.TCP
import DNS.Cache.Server.TLS
import DNS.Cache.Server.Types
import DNS.Cache.Server.UDP
