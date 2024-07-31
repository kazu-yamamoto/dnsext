{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.UDP (
    udpServers,
    UdpServerConfig (..),
)
where

-- GHC packages
import Control.Concurrent.STM
import Control.Monad (void, when)

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import Network.Socket (
    SocketOption (..),
    getSocketName,
    setSocketOption,
 )
import qualified Network.Socket.ByteString as NSB

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsUDP53)

----------------------------------------------------------------

data UdpServerConfig = UdpServerConfig
    { udpAutomaticInterface :: Bool
    }

----------------------------------------------------------------

udpServers :: UdpServerConfig -> ServerActions
udpServers _conf env toCacher ss =
    concat <$> mapM (udpServer _conf env toCacher) ss

udpServer :: UdpServerConfig -> Env -> ToCacher -> Socket -> IO ([IO ()])
udpServer UdpServerConfig{..} env toCacher s = do
    mysa <- getSocketName s
    when udpAutomaticInterface $ setSocketOption s (decideOption mysa) 1
    qs <- newTQueueIO
    let toSender = atomically . writeTQueue qs
        fromX = atomically $ readTQueue qs
        recv
            | udpAutomaticInterface = do
                (peersa, bs, cmsgs, _) <- NSB.recvMsg s 2048 2048 0
                incStatsUDP53 peersa (stats_ env)
                return (bs, PeerInfoUDP peersa cmsgs)
            | otherwise = do
                (bs, peersa) <- NSB.recvFrom s 2048
                incStatsUDP53 peersa (stats_ env)
                return (bs, PeerInfoUDP peersa [])
        send bs (PeerInfoUDP peersa cmsgs)
            | udpAutomaticInterface =
                void $ NSB.sendMsg s peersa [bs] cmsgs 0
            | otherwise = void $ NSB.sendTo s bs peersa
        send _ _ = return ()
        receiver = receiverLogic env mysa recv toCacher toSender UDP
        sender = senderLogic env send fromX
    return [TStat.concurrently_ "udp-send" sender "udp-recv" receiver]

decideOption :: SockAddr -> SocketOption
decideOption SockAddrInet{} = RecvIPv4PktInfo
decideOption SockAddrInet6{} = RecvIPv6PktInfo
decideOption _ = error "decideOption"
