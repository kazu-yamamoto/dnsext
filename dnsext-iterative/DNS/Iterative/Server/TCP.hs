{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TCP where

-- GHC packages
import Control.Monad (when)
import qualified Data.ByteString as BS

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages
import Control.Concurrent.Async
import qualified DNS.Do53.Internal as DNS
import Network.Run.TCP
import Network.Socket (getPeerName, getSocketName)
import qualified System.TimeManager as T

-- this package
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

----------------------------------------------------------------

tcpServer :: VcServerConfig -> Server
tcpServer VcServerConfig{..} env toCacher port host = do
    let tcpserver = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            runTCPServer (Just host) (show port) $ go mgr
    return ([tcpserver])
  where
    maxSize = fromIntegral vc_query_max_size
    go mgr sock = do
        mysa <- getSocketName sock
        peersa <- getPeerName sock
        let peerInfo = PeerInfoVC peersa
        (toSender, fromX) <- mkConnector
        th <- T.registerKillThread mgr $ return ()
        let recv = do
                (siz, bss) <- DNS.recvVC maxSize $ DNS.recvTCP sock
                if siz == 0
                    then return ("", peerInfo)
                    else do
                        when (siz > vc_slowloris_size) $ T.tickle th
                        return (BS.concat bss, peerInfo)
            send bs _ = do
                DNS.sendVC (DNS.sendTCP sock) bs
                T.tickle th
            receiver = receiverLogicVC env mysa recv toCacher toSender TCP
            sender = senderLogicVC env send fromX
        concurrently_ sender receiver
