{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.UDP (
    udpServers,
    UdpServerConfig (..),
)
where

-- GHC packages
import Control.Concurrent.STM

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import Network.Socket (getSocketName)
import qualified Network.UDP as UDP

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsUDP53)

----------------------------------------------------------------

data UdpServerConfig = UdpServerConfig {}

----------------------------------------------------------------

udpServers :: UdpServerConfig -> ServerActions
udpServers _conf env toCacher ss =
    concat <$> mapM (udpServer _conf env toCacher) ss

udpServer :: UdpServerConfig -> Env -> ToCacher -> Socket -> IO ([IO ()])
udpServer _conf env toCacher s = do
    sa <- getSocketName s
    let lsock = UDP.ListenSocket s sa False -- interface specific
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
