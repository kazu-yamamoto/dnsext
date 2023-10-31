{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.UDP where

-- GHC packages
import Control.Concurrent.STM

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages
import qualified Network.UDP as UDP

-- this package
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

----------------------------------------------------------------

data UdpServerConfig = UdpServerConfig {}

----------------------------------------------------------------

udpServer :: UdpServerConfig -> Server
udpServer _conf env toCacher port addr = do
    lsock <- UDP.serverSocket (read addr, port)
    qs <- newTQueueIO
    let toSender = atomically . writeTQueue qs
        fromX = atomically $ readTQueue qs
        mysa = UDP.mySockAddr lsock
        recv = do
            (bs, csa) <- UDP.recvFrom lsock
            return (bs, PeerInfoUDP csa)
        send bs peerInfo = do
            case peerInfo of
                PeerInfoUDP csa -> UDP.sendTo lsock bs csa
                _ -> return ()
        receiver = receiverLogic env mysa recv toCacher toSender UDP
        sender = senderLogic env send fromX
    return [receiver, sender]
