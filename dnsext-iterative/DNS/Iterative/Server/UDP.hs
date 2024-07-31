{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.UDP (
    udpServers,
    UdpServerConfig (..),
)
where

-- GHC packages
import Control.Concurrent.STM
import Control.Monad (void)

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import Network.Socket (getSocketName)
import qualified Network.Socket.ByteString as NSB

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
    mysa <- getSocketName s
    qs <- newTQueueIO
    let toSender = atomically . writeTQueue qs
        fromX = atomically $ readTQueue qs
        recv = do
            (bs, peersa) <- NSB.recvFrom s 2048
            incStatsUDP53 peersa (stats_ env)
            return (bs, PeerInfoUDP peersa)
        send bs peerInfo = do
            case peerInfo of
                PeerInfoUDP peersa -> void $ NSB.sendTo s bs peersa
                _ -> return ()
        receiver = receiverLogic env mysa recv toCacher toSender UDP
        sender = senderLogic env send fromX
    return [TStat.concurrently_ "udp-send" sender "udp-recv" receiver]
