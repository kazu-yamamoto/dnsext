module DNS.Cache.Server (
    -- * Types
    Server,
    HostName,
    PortNumber,
    Env(..),
    newEnv,
    RRCacheOps(..),
    newRRCacheOps,
    TimeCache(..),
    newTimeCache,
    -- * UDP
    UdpServerConfig (..),
    udpServer,
    -- * Virtual circuit
    VcServerConfig (..),
    tcpServer,
    http2cServer,
    http2Server,
    http3Server,
    tlsServer,
    quicServer,
    -- * Misc
    Status,
) where

import DNS.Cache.Iterative.Env
import DNS.Cache.Server.HTTP2
import DNS.Cache.Server.HTTP3
import DNS.Cache.Server.QUIC
import DNS.Cache.Server.TCP
import DNS.Cache.Server.TLS
import DNS.Cache.Server.Types
import DNS.Cache.Server.UDP
import DNS.Cache.TimeCache (TimeCache(..), newTimeCache)
import DNS.Do53.RRCache (RRCacheOps(..), newRRCacheOps)
