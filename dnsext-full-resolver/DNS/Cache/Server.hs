module DNS.Cache.Server (
    UdpServerConfig (..),
    udpServer,
    TcpServerConfig (..),
    tcpServer,
    Status,
) where

import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.TCP
import DNS.Cache.Server.UDP
