module DNS.Iterative.Server (
    -- * Types
    Server,
    HostName,
    PortNumber,
    Env (..),
    newEnv,
    RRCacheOps (..),
    newRRCacheOps,
    TimeCache (..),
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

import DNS.Iterative.Query.Env
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.HTTP3
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.TCP
import DNS.Iterative.Server.TLS
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP
import DNS.RRCache (RRCacheOps (..), newRRCacheOps)
import DNS.TimeCache (TimeCache (..), newTimeCache)
