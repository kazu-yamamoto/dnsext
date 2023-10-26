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

    -- * Making recv
    recvManyN,
    recvManyNN,
)
where

import qualified Control.Exception as E
import DNS.Do53.Imports
import DNS.Do53.Types
import DNS.Types hiding (Seconds)
import qualified Data.ByteString as BS
import Network.Socket (
    AddrInfo (..),
    AddrInfoFlag (..),
    HostName,
    PortNumber,
    Socket,
    SocketType (..),
    connect,
    defaultHints,
    getAddrInfo,
    openSocket,
 )
import Network.Socket.ByteString (recv)
import qualified Network.Socket.ByteString as NSB

----------------------------------------------------------------

-- | Opening a TCP socket.
openTCP :: HostName -> PortNumber -> IO Socket
openTCP h p = do
    ai <- makeAddrInfo h p
    sock <- openSocket ai
    connect sock $ addrAddress ai
    return sock

makeAddrInfo :: HostName -> PortNumber -> IO AddrInfo
makeAddrInfo nh p = do
    let hints =
            defaultHints
                { addrFlags = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_NUMERICSERV]
                , addrSocketType = Stream
                }
    let np = show p
    head <$> getAddrInfo (Just hints) (Just nh) (Just np)

----------------------------------------------------------------

-- TCP and QUIC has its own RecvN.
-- TLS has Recv. This must be converted to RecvN by makeRecvN in the
-- "recv" package. If not converted, a message is also read when
-- obtaining the length of the message!

-- | Receiving data from a virtual circuit.
recvVC :: VCLimit -> RecvN -> RecvMany
recvVC lim recvN = do
    (l2, b2) <- recvManyNN recvN 2
    if l2 /= 2
        then return (0,[])
        else do
            let len = decodeVCLength $ BS.concat b2
            when (fromIntegral len > lim) $
                E.throwIO $
                    DecodeError $
                        "length is over the limit: should be len <= lim, but (len: "
                            ++ show len
                            ++ ") > (lim: "
                            ++ show lim
                            ++ ") "
            (len', bss) <- recvManyNN recvN len
            case compare len' len of
                LT -> E.throwIO $ DecodeError "message length is not enough"
                EQ -> return (len, bss)
                GT -> E.throwIO $ DecodeError "message length is too large"

-- | Decoding the length from the first two bytes.
decodeVCLength :: ByteString -> Int
decodeVCLength bs = case BS.unpack bs of
    [hi, lo] -> 256 * fromIntegral hi + fromIntegral lo
    _ -> 0 -- never reached

-- Used only in DoH.
-- Recv is getResponseBodyChunk.
-- "lim" is a really limitation
recvManyN :: Recv -> RecvManyN
recvManyN rcv lim = loop id 0
  where
    loop build total = do
        bs <- rcv
        let len = BS.length bs
        if len == 0
            then return (total, build [])
            else do
                let total' = total + len
                    build' = build . (bs :)
                if total' >= lim
                    then do
                        return (total', build' [])
                    else loop build' total'

-- Used only in recvVC.
-- "lim" is the size to be received.
recvManyNN :: RecvN -> RecvManyN
recvManyNN rcv lim = loop id 0
  where
    loop build total = do
        let left = lim - total
            siz = min left 2048
        bs <- rcv siz
        let len = BS.length bs
        if len == 0
            then return (total, build [])
            else do
                let total' = total + len
                    build' = build . (bs :)
                if total' >= lim
                    then do
                        return (total', build' [])
                    else loop build' total'

-- | Receiving data from a TCP socket.
recvTCP :: Socket -> RecvN
recvTCP sock = recv sock

----------------------------------------------------------------

-- | Send a single encoded 'DNSMessage' over VC.  An explicit length is
-- prepended to the encoded buffer before transmission.  If you want to
-- send a batch of multiple encoded messages back-to-back over a single
-- VC connection, and then loop to collect the results, use 'encodeVC'
-- to prefix each message with a length, and then use 'sendAll' to send
-- a concatenated batch of the resulting encapsulated messages.
sendVC :: SendMany -> Send
sendVC writev bs = do
    let lb = encodeVCLength $ BS.length bs
    writev [lb, bs]

-- | Sending data to a TCP socket.
sendTCP :: Socket -> SendMany
sendTCP = NSB.sendMany

-- | Encapsulate an encoded 'DNSMessage' buffer for transmission over a VC
-- virtual circuit.  With VC the buffer needs to start with an explicit
-- length (the length is implicit with UDP).
encodeVCLength :: Int -> ByteString
encodeVCLength len = BS.pack [fromIntegral u, fromIntegral l]
  where
    (u, l) = len `divMod` 256
