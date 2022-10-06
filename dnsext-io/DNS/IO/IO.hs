{-# LANGUAGE OverloadedStrings #-}

module DNS.IO.IO (
    -- * Receiving DNS messages
    receive
  , receiveFrom
  , receiveVC
    -- * Sending pre-encoded messages
  , send
  , sendTo
  , sendVC
  , sendAll
    -- ** Encoding queries for transmission
  , encodeVC
  ) where

import qualified Control.Exception as E
import DNS.Types
import DNS.Types.Decode
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy.Char8 as LC8
import Network.Socket (Socket, SockAddr)
import Network.Socket.ByteString (recv, recvFrom)
import qualified Network.Socket.ByteString as Socket
import System.IO.Error
import Time.System (timeCurrent)
import Time.Types (Elapsed(..), Seconds(..))

import DNS.IO.Imports

----------------------------------------------------------------

-- | Receive and decode a single 'DNSMessage' from a UDP 'Socket', throwing away
-- the client address.  Messages longer than 'maxUdpSize' are silently
-- truncated, but this should not occur in practice, since we cap the advertised
-- EDNS UDP buffer size limit at the same value.  A 'DNSError' is raised if I/O
-- or message decoding fails.
--
receive :: Socket -> IO DNSMessage
receive sock = do
    let bufsiz = fromIntegral maxUdpSize
    bs <- recv sock bufsiz `E.catch` \e -> E.throwIO $ NetworkFailure e
    Elapsed (Seconds now) <- timeCurrent
    case decodeAt defaultDecodeDict now bs of
        Left  e   -> E.throwIO e
        Right msg -> return msg

-- | Receive and decode a single 'DNSMessage' from a UDP 'Socket'.  Messages
-- longer than 'maxUdpSize' are silently truncated, but this should not occur
-- in practice, since we cap the advertised EDNS UDP buffer size limit at the
-- same value.  A 'DNSError' is raised if I/O or message decoding fails.
--
receiveFrom :: Socket -> IO (DNSMessage, SockAddr)
receiveFrom sock = do
    let bufsiz = fromIntegral maxUdpSize
    (bs, client) <- recvFrom sock bufsiz `E.catch` \e -> E.throwIO $ NetworkFailure e
    Elapsed (Seconds now) <- timeCurrent
    case decodeAt defaultDecodeDict now bs of
        Left  e   -> E.throwIO e
        Right msg -> return (msg, client)

-- | Receive and decode a single 'DNSMesage' from a virtual-circuit (TCP).  It
-- is up to the caller to implement any desired timeout. An 'DNSError' is
-- raised if I/O or message decoding fails.
--
receiveVC :: Socket -> IO DNSMessage
receiveVC sock = do
    len <- toLen <$> recvDNS sock 2
    bs <- recvDNS sock len
    Elapsed (Seconds now) <- timeCurrent
    case decodeAt defaultDecodeDict now bs of
        Left e    -> E.throwIO e
        Right msg -> return msg
  where
    toLen bs = case BS.unpack bs of
        [hi, lo] -> 256 * (fromIntegral hi) + (fromIntegral lo)
        _        -> 0              -- never reached

recvDNS :: Socket -> Int -> IO ByteString
recvDNS sock len = recv1 `E.catch` \e -> E.throwIO $ NetworkFailure e
  where
    recv1 = do
        bs1 <- recvCore len
        if C8.length bs1 == len then
            return bs1
          else do
            loop bs1
    loop bs0 = do
        let left = len - C8.length bs0
        bs1 <- recvCore left
        let bs = bs0 `C8.append` bs1
        if C8.length bs == len then
            return bs
          else
            loop bs
    eofE = mkIOError eofErrorType "connection terminated" Nothing Nothing
    recvCore len0 = do
        bs <- recv sock len0
        if bs == "" then
            E.throwIO eofE
          else
            return bs

----------------------------------------------------------------

-- | Send an encoded 'DNSMessage' datagram over UDP.  The message length is
-- implicit in the size of the UDP datagram.  With TCP you must use 'sendVC',
-- because TCP does not have message boundaries, and each message needs to be
-- prepended with an explicit length.  The socket must be explicitly connected
-- to the destination nameserver.
--
send :: Socket -> ByteString -> IO ()
send = (void .). Socket.send
{-# INLINE send #-}

-- | Send an encoded 'DNSMessage' datagram over UDP to a given address.  The
-- message length is implicit in the size of the UDP datagram.  With TCP you
-- must use 'sendVC', because TCP does not have message boundaries, and each
-- message needs to be prepended with an explicit length.
--
sendTo :: Socket -> ByteString -> SockAddr -> IO ()
sendTo sock str addr = Socket.sendTo sock str addr >> return ()
{-# INLINE sendTo #-}

-- | Send a single encoded 'DNSMessage' over TCP.  An explicit length is
-- prepended to the encoded buffer before transmission.  If you want to
-- send a batch of multiple encoded messages back-to-back over a single
-- TCP connection, and then loop to collect the results, use 'encodeVC'
-- to prefix each message with a length, and then use 'sendAll' to send
-- a concatenated batch of the resulting encapsulated messages.
--
sendVC :: Socket -> ByteString -> IO ()
sendVC = (. encodeVC). sendAll
{-# INLINE sendVC #-}

-- | Send one or more encoded 'DNSMessage' buffers over TCP, each allready
-- encapsulated with an explicit length prefix (perhaps via 'encodeVC') and
-- then concatenated into a single buffer.  DO NOT use 'sendAll' with UDP.
--
sendAll :: Socket -> ByteString -> IO ()
sendAll = Socket.sendAll
{-# INLINE sendAll #-}

-- | Encapsulate an encoded 'DNSMessage' buffer for transmission over a TCP
-- virtual circuit.  With TCP the buffer needs to start with an explicit
-- length (the length is implicit with UDP).
--
encodeVC :: ByteString -> ByteString
encodeVC legacyQuery =
    let len = LC8.toStrict . BB.toLazyByteString $ BB.int16BE $ fromIntegral $ C8.length legacyQuery
    in len <> legacyQuery
{-# INLINE encodeVC #-}
