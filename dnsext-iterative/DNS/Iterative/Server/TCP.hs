{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TCP where

-- GHC packages
import Control.Monad (when)

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages
import qualified DNS.Do53.Internal as DNS
import Network.Run.TCP
import Network.Socket (getPeerName, getSocketName)
import qualified System.TimeManager as T

-- this package
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

----------------------------------------------------------------
tcpServer :: VcServerConfig -> Server
tcpServer VcServerConfig{..} env port host = do
    (cntget, cntinc) <- newCounters
    let tcpserver = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            runTCPServer (Just host) (show port) $ \sock -> do
                mysa <- getSocketName sock
                peersa <- getPeerName sock
                th <- T.registerKillThread mgr $ return ()
                let send bs = do
                        DNS.sendVC (DNS.sendTCP sock) bs
                        T.tickle th
                    recv = do
                        bss@(siz, _) <- DNS.recvVC maxSize $ DNS.recvTCP sock
                        when (siz > vc_slowloris_size) $ T.tickle th
                        return bss
                (_n, bss) <- recv
                cacheWorkerLogic env cntinc send TCP mysa peersa bss
    return ([tcpserver], [readCounters cntget])
  where
    maxSize = fromIntegral vc_query_max_size
