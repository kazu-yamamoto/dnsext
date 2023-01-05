module DNS.Cache.DNSUtil (
  mkRecvBS, mkSendBS,
  mkRecv, mkSend,
  lookupRaw,

  -- interfaces to check compile-time configs
  isRecvSendMsg,
  ) where

-- GHC packages
import qualified Control.Exception as E
import Control.Monad (void)
import Data.Int (Int64)
import Data.ByteString (ByteString)

-- dns packages
import Network.Socket (Socket, SockAddr)
import qualified Network.Socket as Socket
import qualified Network.Socket.ByteString as Socket
import DNS.Types (DNSMessage)
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import qualified DNS.Do53.Client as DNS

---

type Cmsg = Socket.Cmsg

mkRecvBS :: Bool -> Socket -> IO (ByteString, (SockAddr, [Cmsg]))
mkRecvBS wildcard
  | wildcard    =  withRecv recvMsg
  | otherwise   =  withRecv recvFrom
  where
    withRecv recv sock = recv sock `E.catch` \e -> E.throwIO $ DNS.NetworkFailure e
    recvMsg sock = do
      let cbufsiz = 64
      (peer, bs, cmsgs, _) <- Socket.recvMsg sock bufsiz cbufsiz 0
      return (bs, (peer, cmsgs))

    recvFrom sock = do
      (bs, peer) <- Socket.recvFrom sock bufsiz
      return (bs, (peer, []))
    bufsiz = 2048 -- large enough, no locking

-- return tuples that can be reused in request and response queues
mkRecv :: Bool -> Int64 -> Socket -> IO (DNSMessage, (SockAddr, [Cmsg]))
mkRecv wildcard now
  | wildcard    =  recvDNS recvMsg
  | otherwise   =  recvDNS recvFrom
  where
    recvDNS recv sock = do
      (bs, ai) <- recv sock `E.catch` \e -> E.throwIO $ DNS.NetworkFailure e
      case DNS.decodeAt now bs of
        Left  e   -> E.throwIO e
        Right msg -> return (msg, ai)

    recvMsg sock = do
      let cbufsiz = 64
      (peer, bs, cmsgs, _) <- Socket.recvMsg sock bufsiz cbufsiz 0
      return (bs, (peer, cmsgs))

    recvFrom sock = do
      (bs, peer) <- Socket.recvFrom sock bufsiz
      return (bs, (peer, []))
    bufsiz = 2048 -- large enough, no locking

mkSendBS :: Bool -> Socket -> ByteString -> SockAddr -> [Cmsg] -> IO ()
mkSendBS wildcard
  | wildcard   =  sendMsg
  | otherwise  =  sendTo
  where
    sendMsg sock bs addr cmsgs = void $ Socket.sendMsg sock addr [bs] cmsgs 0

    sendTo sock bs addr _ = void $ Socket.sendTo sock bs addr

mkSend :: Bool -> Socket -> DNSMessage -> SockAddr -> [Cmsg] -> IO ()
mkSend wildcard
  | wildcard   =  sendDNS sendMsg
  | otherwise  =  sendDNS sendTo
  where
    sendDNS send sock msg addr cmsgs =
      void $ send sock (DNS.encode msg) addr cmsgs

    sendMsg sock bs addr cmsgs = Socket.sendMsg sock addr [bs] cmsgs 0

    sendTo sock bs addr _ = Socket.sendTo sock bs addr

-- available recvMsg and sendMsg or not
isRecvSendMsg :: Bool
isRecvSendMsg = True

---

lookupRaw :: Int64 -> DNS.Resolver -> DNS.Domain -> DNS.TYPE -> IO (Either DNS.DNSError DNSMessage)
lookupRaw now rslv dom typ = DNS.lookupRawCtlTime rslv dom typ mempty (return now)
