{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.TCP where

-- GHC packages

-- dnsext-* packages

-- other packages

import qualified DNS.Do53.Internal as DNS
import Network.Run.TCP

-- this package
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.Types

----------------------------------------------------------------
data TcpServerConfig = TcpServerConfig
    { tcp_idle_timeout :: Int
    }

tcpServer :: TcpServerConfig -> Server
tcpServer _tcpconf env port host = do
    (cntget, cntinc) <- newCounters
    let tcpserver = runTCPServer (Just host) (show port) $ \sock -> do
            let send = DNS.sendVC $ DNS.sendTCP sock
                recv = DNS.recvVC 2048 $ DNS.recvTCP sock
            (_n, bss) <- recv
            cacheWorkerLogic env cntinc send bss
    return ([tcpserver], [readCounters cntget])
