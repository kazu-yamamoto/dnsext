module DNS.Cache.Server (
    UdpServerConfig (..),
    udpServer,
    TcpServerConfig (..),
    tcpServer,
    Http2cServerConfig (..),
    http2cServer,
    Status,
) where

import DNS.Cache.Server.HTTP2
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.TCP
import DNS.Cache.Server.UDP
