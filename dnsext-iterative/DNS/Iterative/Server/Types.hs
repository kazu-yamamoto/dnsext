module DNS.Iterative.Server.Types (
    Server,
    Env,
    HostName,
    PortNumber,
    VcServerConfig (..),
    Fuel (..),
    ToCacher,
    FromX,
    PeerInfo(..),
    peerSockAddr,
) where

import DNS.Iterative.Query (Env)
import DNS.TAP.Schema (SocketProtocol)
import DNS.Types (DNSMessage)
import qualified Network.QUIC as QUIC
import Network.Socket
import qualified Network.UDP as UDP

data PeerInfo = PeerInfoUDP UDP.ClientSockAddr
              | PeerInfoQUIC SockAddr QUIC.Stream
              | PeerInfoVC SockAddr

peerSockAddr :: PeerInfo -> SockAddr
peerSockAddr (PeerInfoUDP (UDP.ClientSockAddr sa _)) = sa
peerSockAddr (PeerInfoQUIC sa _) = sa
peerSockAddr (PeerInfoVC sa) = sa

data Fuel = Fuel
    { fuelQuery :: DNSMessage
    , fuelReply :: DNSMessage
    , fuelMysa :: SockAddr
    , fuelPeerInfo :: PeerInfo
    , fuelProto :: SocketProtocol
    , fuelToSender :: Fuel -> IO () -- very tricky
    }

type ToCacher = Fuel -> IO ()
type FromX = IO Fuel

type Server = Env -> ToCacher -> PortNumber -> HostName -> IO ([IO ()])

data VcServerConfig = VcServerConfig
    { vc_query_max_size :: Int
    , vc_idle_timeout :: Int
    , vc_slowloris_size :: Int
    }
