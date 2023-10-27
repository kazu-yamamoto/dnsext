module DNS.Iterative.Server.Types (
    Server,
    Env,
    HostName,
    PortNumber,
    VcServerConfig (..),
    ToCacher,
    FromReciver,
    ToWorker,
    FromCacher,
    ToSender,
    FromX,
    Input(..),
    Output(..),
    PeerInfo(..),
    peerSockAddr,
) where

import DNS.Iterative.Query (Env)
import DNS.TAP.Schema (SocketProtocol)
import DNS.Types (DNSMessage)
import Data.ByteString (ByteString)
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

data Input a = Input
    { inputQuery :: a
    , inputMysa :: SockAddr
    , inputPeerInfo :: PeerInfo
    , inputProto :: SocketProtocol
    , inputToSender :: ToSender
    }

data Output = Output
    { outputReplyBS :: ByteString
    , outputPeerInfo :: PeerInfo
    }

type ToCacher = Input ByteString -> IO ()
type FromReciver = IO (Input ByteString)
type ToWorker = Input DNSMessage -> IO ()
type FromCacher = IO (Input DNSMessage)
type ToSender = Output -> IO ()
type FromX = IO Output

type Server = Env -> ToCacher -> PortNumber -> HostName -> IO ([IO ()])

data VcServerConfig = VcServerConfig
    { vc_query_max_size :: Int
    , vc_idle_timeout :: Int
    , vc_slowloris_size :: Int
    }
