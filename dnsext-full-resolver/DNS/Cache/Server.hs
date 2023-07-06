module DNS.Cache.Server (
    UdpServerConfig (..),
    udpServer,
    Status,
) where

import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.UDP
