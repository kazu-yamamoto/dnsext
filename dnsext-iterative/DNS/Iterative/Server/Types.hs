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
    ReqNum,
    Input (..),
    Output (..),
    PeerInfo (..),
    peerSockAddr,
    withLocationIOE,
) where

-- GHC
import Data.ByteString (ByteString)
import System.IO.Error (ioeSetLocation, tryIOError)

-- libs
import qualified Network.HTTP2.Server.Internal as H2I
import qualified Network.QUIC as QUIC
import Network.Socket
import Network.TLS (Credentials (..), SessionManager)
import qualified Network.UDP as UDP

-- dnsext
import DNS.TAP.Schema (SocketProtocol)
import DNS.Types (DNSMessage)

-- this package
import DNS.Iterative.Query (Env)

data PeerInfo
    = PeerInfoUDP UDP.ClientSockAddr
    | PeerInfoQUIC SockAddr QUIC.Stream
    | PeerInfoH2 SockAddr H2I.Stream
    | PeerInfoVC SockAddr
    deriving Show

peerSockAddr :: PeerInfo -> SockAddr
peerSockAddr (PeerInfoUDP (UDP.ClientSockAddr sa _)) = sa
peerSockAddr (PeerInfoQUIC sa _) = sa
peerSockAddr (PeerInfoH2 sa _) = sa
peerSockAddr (PeerInfoVC sa) = sa

-- request identifier in one connection
type ReqNum = Int

data Input a = Input
    { inputQuery :: a
    , inputRequestNum :: ReqNum
    , inputMysa :: SockAddr
    , inputPeerInfo :: PeerInfo
    , inputProto :: SocketProtocol
    , inputToSender :: ToSender
    }

data Output = Output
    { outputReplyBS :: ByteString
    , outputRequestNum :: ReqNum
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
