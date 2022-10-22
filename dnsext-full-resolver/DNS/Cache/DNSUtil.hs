{-# LANGUAGE CPP #-}

module DNS.Cache.DNSUtil (
  mkRecvBS, mkSendBS,
  mkRecv, mkSend,
  lookupRaw,

  -- interfaces to check compile-time configs
  isRecvSendMsg,
  isExtendedLookup,
  ) where

-- GHC packages
import qualified Control.Exception as E
import Control.Monad (void)
import Data.Int (Int64)
import Data.ByteString (ByteString)

-- dns packages
import Network.Socket (Socket, SockAddr)
#if MIN_VERSION_network(3,1,2)
import qualified Network.Socket as Socket
#endif
import qualified Network.Socket.ByteString as Socket
import DNS.Types (DNSMessage)
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import qualified DNS.IO as DNS

---

#if MIN_VERSION_network(3,1,2)
type Cmsg = Socket.Cmsg
#else
type Cmsg = ()
#endif

mkRecvBS :: Bool -> Socket -> IO (ByteString, (SockAddr, [Cmsg]))
#if MIN_VERSION_network(3,1,2)
mkRecvBS wildcard
  | wildcard    =  withRecv recvMsg
  | otherwise   =  withRecv recvFrom
#else
mkRecvBS _      =  withRecv recvFrom
#endif
  where
    withRecv recv sock = recv sock `E.catch` \e -> E.throwIO $ DNS.NetworkFailure e
#if MIN_VERSION_network(3,1,2)
    recvMsg sock = do
      let cbufsiz = 64
      (peer, bs, cmsgs, _) <- Socket.recvMsg sock bufsiz cbufsiz 0
      return (bs, (peer, cmsgs))
#endif

    recvFrom sock = do
      (bs, peer) <- Socket.recvFrom sock bufsiz
      return (bs, (peer, []))
    bufsiz = 16384 -- maxUdpSize in dns package, internal/Network/DNS/Types/Internal.hs

-- return tuples that can be reused in request and response queues
mkRecv :: Bool -> Int64 -> Socket -> IO (DNSMessage, (SockAddr, [Cmsg]))
#if MIN_VERSION_network(3,1,2)
mkRecv wildcard now
  | wildcard    =  recvDNS recvMsg
  | otherwise   =  recvDNS recvFrom
#else
mkRecv _        now =  recvDNS recvFrom
#endif
  where
    recvDNS recv sock = do
      (bs, ai) <- recv sock `E.catch` \e -> E.throwIO $ DNS.NetworkFailure e
      case DNS.decodeAt now bs of
        Left  e   -> E.throwIO e
        Right msg -> return (msg, ai)

#if MIN_VERSION_network(3,1,2)
    recvMsg sock = do
      let cbufsiz = 64
      (peer, bs, cmsgs, _) <- Socket.recvMsg sock bufsiz cbufsiz 0
      return (bs, (peer, cmsgs))
#endif

    recvFrom sock = do
      (bs, peer) <- Socket.recvFrom sock bufsiz
      return (bs, (peer, []))
    bufsiz = 16384 -- maxUdpSize in dns package, internal/Network/DNS/Types/Internal.hs

mkSendBS :: Bool -> Socket -> ByteString -> SockAddr -> [Cmsg] -> IO ()
#if MIN_VERSION_network(3,1,2)
mkSendBS wildcard
  | wildcard   =  sendMsg
  | otherwise  =  sendTo
#else
mkSendBS _     =  sendTo
#endif
  where
#if MIN_VERSION_network(3,1,2)
    sendMsg sock bs addr cmsgs = void $ Socket.sendMsg sock addr [bs] cmsgs 0
#endif

    sendTo sock bs addr _ = void $ Socket.sendTo sock bs addr

mkSend :: Bool -> Socket -> DNSMessage -> SockAddr -> [Cmsg] -> IO ()
#if MIN_VERSION_network(3,1,2)
mkSend wildcard
  | wildcard   =  sendDNS sendMsg
  | otherwise  =  sendDNS sendTo
#else
mkSend _       =  sendDNS sendTo
#endif
  where
    sendDNS send sock msg addr cmsgs =
      void $ send sock (DNS.encode msg) addr cmsgs

#if MIN_VERSION_network(3,1,2)
    sendMsg sock bs addr cmsgs = Socket.sendMsg sock addr [bs] cmsgs 0
#endif

    sendTo sock bs addr _ = Socket.sendTo sock bs addr

-- available recvMsg and sendMsg or not
isRecvSendMsg :: Bool
#if MIN_VERSION_network(3,1,2)
isRecvSendMsg = True
#else
isRecvSendMsg = False
#endif

---

lookupRaw :: Int64 -> DNS.Resolver -> DNS.Domain -> DNS.TYPE -> IO (Either DNS.DNSError DNSMessage)
isExtendedLookup :: Bool
#if EXTENDED_LOOKUP
lookupRaw now rslv dom typ = DNS.lookupRawCtlRecv rslv dom typ mempty rcv
  where
    rcv sock = do
      bs <- Socket.recv sock bufsiz
      case DNS.decodeAt now bs of
        Left  e   -> E.throwIO e
        Right msg -> return msg
    bufsiz = 16384 -- maxUdpSize in dns package, internal/Network/DNS/Types/Internal.hs

isExtendedLookup = True
#else
lookupRaw _ = DNS.lookupRaw

isExtendedLookup = False
#endif
