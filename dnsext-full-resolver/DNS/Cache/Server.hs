module DNS.Cache.Server (
    UdpServerConfig (..),
    udpServer,
    TcpServerConfig (..),
    tcpServer,
    Http2cServerConfig (..),
    http2cServer,
    Http2ServerConfig (..),
    http2Server,
    TlsServerConfig (..),
    tlsServer,
    Status,
    Server,
    Env,
    HostName,
    PortNumber,
) where

import DNS.Cache.Server.HTTP2
import DNS.Cache.Server.TCP
import DNS.Cache.Server.TLS
import DNS.Cache.Server.Types
import DNS.Cache.Server.UDP
