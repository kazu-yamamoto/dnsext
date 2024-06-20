{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.UDP where

-- GHC packages
import Control.Concurrent.STM

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import qualified Network.UDP as UDP

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsUDP53)

----------------------------------------------------------------

data UdpServerConfig = UdpServerConfig {}

----------------------------------------------------------------

udpServer :: UdpServerConfig -> Server
udpServer _conf env toCacher port addr = do
    lsock <- withLocationIOE (show addr ++ ":" ++ show port ++ "/udp") $ UDP.serverSocket (read addr, port)
    qs <- newTQueueIO
    let toSender = atomically . writeTQueue qs
        fromX = atomically $ readTQueue qs
        mysa = UDP.mySockAddr lsock
        recv = do
            (bs, csa@(UDP.ClientSockAddr csa' _)) <- UDP.recvFrom lsock
            incStatsUDP53 csa' (stats_ env)
            return (bs, PeerInfoUDP csa)
        send bs peerInfo = do
            case peerInfo of
                PeerInfoUDP csa -> UDP.sendTo lsock bs csa
                _ -> return ()
        receiver = receiverLogic env mysa recv toCacher toSender UDP
        sender = senderLogic env send fromX
    return [TStat.concurrently_ "udp-send" sender "udp-recv" receiver]
