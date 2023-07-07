{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.TCP where

-- GHC packages

-- dnsext-* packages

-- other packages

import qualified DNS.Do53.Internal as DNS
import Network.Run.TCP
import Network.Socket (
    HostName,
    PortNumber,
 )

-- this package
import DNS.Cache.Iterative (Env (..))
import DNS.Cache.Server.Pipeline

----------------------------------------------------------------
data TcpServerConfig = TcpServerConfig
    { tcp_idle_timeout :: Int
    }

tcpServer
    :: TcpServerConfig
    -> Env
    -> PortNumber
    -> HostName
    -> IO ([IO ()], [IO Status])
tcpServer _tcpconf env port host = do
    (cntget, cntinc) <- newCounters
    let tcpserver = runTCPServer (Just host) (show port) $ \sock -> do
            let send = DNS.sendVC $ DNS.sendTCP sock
                recv = DNS.recvVC 2048 $ DNS.recvTCP sock
            (_n, bss) <- recv
            cacheWorkerLogic env cntinc send bss
    return ([tcpserver], [readCounters cntget])
