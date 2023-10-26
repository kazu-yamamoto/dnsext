{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TLS where

-- GHC packages
import qualified Data.ByteString as BS

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages
import Control.Concurrent.Async
import qualified Network.HTTP2.TLS.Server as H2
import Network.Socket.BufferPool (makeRecvN)
import Network.TLS (Credentials (..))

-- this package
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

tlsServer :: Credentials -> VcServerConfig -> Server
tlsServer creds VcServerConfig{..} env toCacher port host = do
    let tlsserver = H2.runTLS settings creds host port "dot" $ go
    return [tlsserver]
  where
    maxSize = fromIntegral vc_query_max_size
    settings =
        H2.defaultSettings
            { H2.settingsTimeout = vc_idle_timeout
            , H2.settingsSlowlorisSize = vc_slowloris_size
            }
    go _ backend = do
        let mysa = H2.mySockAddr backend
            peersa = H2.peerSockAddr backend
            peerInfo = PeerInfoVC peersa
        recvN <- makeRecvN "" $ H2.recv backend
        (toSender, fromX) <- mkConnector
        let recv = do
                (siz, bss) <- DNS.recvVC maxSize recvN
                if siz == 0
                    then return ("", peerInfo)
                    else return (BS.concat bss, peerInfo)
            send bs _ = DNS.sendVC (H2.sendMany backend) bs
            receiver = receiverLogicVC env mysa recv toCacher toSender DOT
            sender = senderLogicVC env send fromX
        concurrently_ sender receiver

