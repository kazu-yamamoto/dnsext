module DNS.Cache.Server (
    UdpServerConfig (..),
    udpServer,
    TcpServerConfig (..),
    tcpServer,
    Http2ServerConfig (..),
    http2Server,
    Status,
) where

import DNS.Cache.Server.HTTP2
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.TCP
import DNS.Cache.Server.UDP
