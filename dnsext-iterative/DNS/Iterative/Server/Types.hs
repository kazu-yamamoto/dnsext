module DNS.Iterative.Server.Types (
    Server,
    Env,
    HostName,
    PortNumber,
    VcServerConfig (..),
    ToCacher,
    FromReceiver,
    ToWorker,
    FromCacher,
    ToSender,
    FromX,
    Input (..),
    Output (..),
    PeerInfo (..),
    peerSockAddr,
    sockAddrInet6,
    withLocationIOE,
) where

import DNS.Iterative.Query (Env)
import DNS.TAP.Schema (SocketProtocol)
import DNS.Types (DNSMessage)
import Data.ByteString (ByteString)
import qualified Network.HTTP2.Server.Internal as H2I
import qualified Network.QUIC as QUIC
import Network.Socket
import Network.TLS (Credentials (..), SessionManager)
import qualified Network.UDP as UDP
import System.IO.Error (ioeSetLocation, tryIOError)

data PeerInfo
    = PeerInfoUDP UDP.ClientSockAddr
    | PeerInfoQUIC SockAddr QUIC.Stream
    | PeerInfoH2 SockAddr H2I.Stream
    | PeerInfoVC SockAddr

peerSockAddr :: PeerInfo -> SockAddr
peerSockAddr (PeerInfoUDP (UDP.ClientSockAddr sa _)) = sa
peerSockAddr (PeerInfoQUIC sa _) = sa
peerSockAddr (PeerInfoH2 sa _) = sa
peerSockAddr (PeerInfoVC sa) = sa

{- FOURMOLU_DISABLE -}
sockAddrInet6 :: SockAddr -> Bool
sockAddrInet6 SockAddrInet{}  = False
sockAddrInet6 SockAddrInet6{} = True
sockAddrInet6 SockAddrUnix{}  = False

{- FOURMOLU_ENABLE -}

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
type FromReceiver = IO (Input ByteString)
type ToWorker = Input DNSMessage -> IO ()
type FromCacher = IO (Input DNSMessage)
type ToSender = Output -> IO ()
type FromX = IO Output

type Server = Env -> ToCacher -> PortNumber -> HostName -> IO ([IO ()])

data VcServerConfig = VcServerConfig
    { vc_query_max_size :: Int
    , vc_idle_timeout :: Int
    , vc_slowloris_size :: Int
    , vc_credentials :: Credentials
    , vc_session_manager :: SessionManager
    , vc_early_data_size :: Int
    }

withLocationIOE :: String -> IO a -> IO a
withLocationIOE loc action = do
    either left pure =<< tryIOError action
  where
    left ioe = ioError $ ioeSetLocation ioe loc
