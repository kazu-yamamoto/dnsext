
module DNSC.DNSUtil (
  recvFrom, sendTo
  ) where

import qualified Control.Exception as E
import Control.Monad (void)

import Time.System (timeCurrent)
import qualified Time.Types as Time
import Network.Socket (Socket, SockAddr)
import qualified Network.Socket.ByteString as Socket
import Network.DNS (DNSMessage)
import qualified Network.DNS as DNS


---

-- receive DNSMessage from client with address
recvFrom :: Socket -> IO (DNSMessage, SockAddr)
recvFrom sock = do
  let bufsiz = 16384 -- maxUdpSize in dns package, internal/Network/DNS/Types/Internal.hs
  (bs, peer) <- Socket.recvFrom sock bufsiz `E.catch` \e -> E.throwIO $ DNS.NetworkFailure e
  Time.Elapsed (Time.Seconds now) <- timeCurrent
  case DNS.decodeAt now bs of
    Left  e   -> E.throwIO e
    Right msg -> return (msg, peer)

sendTo :: Socket -> DNSMessage -> SockAddr -> IO ()
sendTo sock = (void .) . Socket.sendTo sock . DNS.encode
