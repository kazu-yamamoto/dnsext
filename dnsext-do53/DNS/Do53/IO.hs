{-# LANGUAGE OverloadedStrings #-}

module DNS.Do53.IO (
    openTCP,

    -- * Receiving DNS messages
    recvTCP,
    recvVC,
    decodeVCLength,

    -- * Sending pre-encoded messages
    sendTCP,
    sendVC,
    encodeVCLength,

    -- * Misc
    makeAddrInfo,
)
where

import qualified Control.Exception as E
import DNS.Do53.Imports
import DNS.Do53.Types
import DNS.Types hiding (Seconds)
import qualified Data.ByteString as BS
import Network.Socket (
    AddrInfo (..),
    Family (..),
    SocketType (..),
    connect,
    defaultProtocol,
    openSocket,
 )
import Network.Socket.BufferPool (makeRecvN)
import Network.Socket.ByteString (recv)
import qualified Network.Socket.ByteString as NSB

----------------------------------------------------------------

-- | Opening a TCP socket.
openTCP :: IP -> PortNumber -> IO Socket
openTCP a p = do
    let ai = makeAddrInfo a p
    sock <- openSocket ai
    connect sock $ addrAddress ai
    return sock

makeAddrInfo :: IP -> PortNumber -> AddrInfo
makeAddrInfo a p =
    AddrInfo
        { addrFlags = []
        , addrFamily = case a of
            IPv4 _ -> AF_INET
            IPv6 _ -> AF_INET6
        , addrSocketType = Stream
        , addrProtocol = defaultProtocol
        , addrAddress = toSockAddr (a, p)
        , addrCanonName = Nothing
        }

----------------------------------------------------------------

-- TCP and QUIC has its own RecvN (i.e., Int -> IO BS).
-- TLS has Recv. This must be converted to RecvN by makeRecvN in the
-- "recv" package. If not converted, a message is also read when
-- obtaining the length of the message!

-- | Receiving data from a virtual circuit.
-- This function returns exactly-necessary-length data.
-- If necessary-length data is not received, an exception is thrown.
recvVC :: VCLimit -> IO BS -> IO BS
recvVC lim rcv = do
    recvN <- makeRecvN "" rcv
    b2 <- recvN 2
    let len = decodeVCLength b2
    when (fromIntegral len > lim) $
        E.throwIO $
            DecodeError $
                "length is over the limit: should be len <= lim, but (len: "
                    ++ show len
                    ++ ") > (lim: "
                    ++ show lim
                    ++ ") "
    bs <- recvN len
    if BS.null bs
        then E.throwIO $ DecodeError "message length is not enough"
        else return bs

-- | Decoding the length from the first two bytes.
decodeVCLength :: ByteString -> Int
decodeVCLength bs = case BS.unpack bs of
    [hi, lo] -> 256 * fromIntegral hi + fromIntegral lo
    _ -> 0 -- never reached

-- | Receiving data from a TCP socket.
recvTCP :: Socket -> IO BS
recvTCP sock = recv sock 2048

----------------------------------------------------------------

-- | Send a single encoded 'DNSMessage' over VC.  An explicit length is
-- prepended to the encoded buffer before transmission.  If you want to
-- send a batch of multiple encoded messages back-to-back over a single
-- VC connection, and then loop to collect the results, use 'encodeVC'
-- to prefix each message with a length, and then use 'sendAll' to send
-- a concatenated batch of the resulting encapsulated messages.
sendVC :: ([BS] -> IO ()) -> BS -> IO ()
sendVC writev bs = do
    let lb = encodeVCLength $ BS.length bs
    writev [lb, bs]

-- | Sending data to a TCP socket.
sendTCP :: Socket -> [BS] -> IO ()
sendTCP = NSB.sendMany

-- | Encapsulate an encoded 'DNSMessage' buffer for transmission over a VC
-- virtual circuit.  With VC the buffer needs to start with an explicit
-- length (the length is implicit with UDP).
encodeVCLength :: Int -> ByteString
encodeVCLength len = BS.pack [fromIntegral u, fromIntegral l]
  where
    (u, l) = len `divMod` 256
