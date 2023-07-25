{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Main where

import Control.Concurrent
import Control.Monad
import DNS.Types.Decode
import Data.Bits
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Hexdump
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.BufferPool as P

----------------------------------------------------------------

main :: IO ()
main = do
    lsock <- socket AF_UNIX Stream defaultProtocol
    bind lsock $ SockAddrUnix "/opt/local/etc/unbound/tmp/unbound.sock"
    listen lsock 10
    loop lsock
  where
    loop lsock = forever $ do
        (sock,_) <- accept lsock
        void $ forkIO $ fstrmReader sock

----------------------------------------------------------------

-- Fast stream:
-- https://github.com/farsightsec/fstrm/blob/master/fstrm/control.h

fstrm_control_accept :: Word32
fstrm_control_accept = 0x01
fstrm_control_start :: Word32
fstrm_control_start = 0x02
fstrm_control_stop :: Word32
fstrm_control_stop = 0x03
fstrm_control_ready :: Word32
fstrm_control_ready = 0x04
fstrm_control_finish :: Word32
fstrm_control_finish = 0x05

fstrmReader :: Socket -> IO ()
fstrmReader sock = do
    pool <- P.newBufferPool 512 16384
    recvN <- P.makeRecvN "" $ P.receive sock pool
    fstrmStart recvN
    fstrmData recvN
    fstrmStop

fstrmStart :: P.RecvN -> IO ()
fstrmStart recvN = do
    bsc <- recvN 4
    c <- withReadBuffer bsc $ \rbuf -> fromIntegral <$> read32 rbuf
    when (c /= (0 :: Int)) $ error "start no control"
    bsl <- recvN 4
    l <- withReadBuffer bsl $ \rbuf -> fromIntegral <$> read32 rbuf
    bsx <- recvN l
    withReadBuffer bsx $ \rbuf -> do
        s <- read32 rbuf
        when (s /= fstrm_control_start) $ error "xxx"
        putStrLn "START"
        a <- read32 rbuf
        when (a /= fstrm_control_accept) $ error "xxx"
        l1 <- read32 rbuf
        str <- extractByteString rbuf $ fromIntegral l1
        putStr "ACCEPT "
        C8.putStrLn str

fstrmData :: P.RecvN -> IO ()
fstrmData recvN = loop
  where
    loop = do
        bsl <- recvN 4
        l <- withReadBuffer bsl $ \rbuf -> fromIntegral <$> read32 rbuf
        putStrLn "--------------------------------"
        putStrLn $ "fstrm data length: " ++ show l
        if l == 0
            then return ()
            else do
                bsx <- recvN l
                dnstap bsx
                loop

fstrmStop :: IO ()
fstrmStop = putStrLn "STOP"

----------------------------------------------------------------

-- DNSTAP
-- https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto

dnstap :: ByteString -> IO ()
dnstap bsx = withReadBuffer bsx loop
  where
    loop rbuf = do
        putStr "DNSTAP "
        t <- tag rbuf
        case t of
          (1, LEN) -> do
              putStr "Identity "
              lenPref <- varint rbuf
              str <- extractByteString rbuf lenPref
              C8.putStrLn str
          (2, LEN) -> do
              putStr "Version "
              lenPref <- varint rbuf
              str <- extractByteString rbuf lenPref
              C8.putStrLn str
          (14, LEN) -> do
              putStrLn "Message:"
              lenPref <- varint rbuf
              bs <- extractByteString rbuf lenPref
              message bs
          (15, VARINT) -> do
              putStr "Type "
              varint rbuf >>= print
          (num,wt) -> do
              putStr $ show num ++ " "
              skip rbuf wt
        rest <- remainingSize rbuf
        when (rest /= 0) $ loop rbuf

message :: ByteString -> IO ()
message bs = withReadBuffer bs loop
  where
    loop rbuf = do
        t <- tag rbuf
        case t of
          (1, VARINT) -> do
              putStr "Type "
              varint rbuf >>= putStrLn . messageType
          (2, VARINT) -> do
              putStr "SocketFamily "
              varint rbuf >>= putStrLn . socketFamily
          (3, VARINT) -> do
              putStr "SocketProtocol "
              varint rbuf >>= putStrLn . socketProtocol
          (4, LEN) -> do
              putStr "QueryAddress "
              dump rbuf
          (5, LEN) -> do
              putStr "ResponseAddress "
              dump rbuf
          (6, VARINT) -> do
              putStr "QueryPort "
              varint rbuf >>= print
          (7, VARINT) -> do
              putStr "ResponsePort "
              varint rbuf >>= print
          (8, VARINT) -> do
              putStr "QueryTimeSec "
              varint rbuf >>= print
          (9, I32) -> do
              putStr "QueryTimeNsec "
              i32 rbuf >>= print
          (10, LEN) -> do
              putStr "QueryMessage "
              decodeDNSMessage rbuf
          (11, LEN) -> do
              putStr "QueryZone "
              dump rbuf
          (12, VARINT) -> do
              putStr "ResponseTimeSec "
              varint rbuf >>= print
          (13, I32) -> do
              putStr "ResponseTimeNsec "
              i32 rbuf >>= print
          (14, LEN) -> do
              putStr "ResponseMessage "
              decodeDNSMessage rbuf
          (15, LEN) -> do
              lenPref <- varint rbuf
              bs' <- extractByteString rbuf lenPref
              policy bs'
          (num,wt) -> do
              putStr $ show num ++ " "
              skip rbuf wt
        rest <- remainingSize rbuf
        when (rest /= 0) $ loop rbuf

-- fixme
policy :: ByteString -> IO ()
policy bs = withReadBuffer bs loop
  where
    loop rbuf = do
        putStr "POLICY "
        t <- tag rbuf
        case t of
          (5, LEN) -> do
              putStr "Value "
              dump rbuf
          (num,wt) -> do
              putStr $ show num ++ " "
              skip rbuf wt

decodeDNSMessage :: Readable a => a -> IO ()
decodeDNSMessage rbuf = do
    len <- varint rbuf
    bs <- extractByteString rbuf len
    print $ decode bs

----------------------------------------------------------------
-- enum

dnstapType :: Int -> String
dnstapType 1 = "MESSAGE"
dnstapType _ = "UNKNOWN"

socketFamily :: Int -> String
socketFamily 1 = "IPv4"
socketFamily 2 = "IPv6"
socketFamily _ = "UNKNOWN"

socketProtocol :: Int -> String
socketProtocol 1 = "UDP"
socketProtocol 2 = "TCP"
socketProtocol 3 = "DOT"
socketProtocol 4 = "DOH"
socketProtocol 5 = "DNSCryptUDP"
socketProtocol 6 = "DNSCryptTCP"
socketProtocol 7 = "DOQ"
socketProtocol _ = "UNKNOWN"

match :: Int -> String
match 1 = "QNAME"
match 2 = "CLIENT_IP"
match 3 = "RESPONSE_IP"
match 4 = "NS_NAME"
match 5 = "NS_IP"
match _ = "UNKNOWN"

action :: Int -> String
action 1 = "NXDOMAIN"
action 2 = "NODATA"
action 3 = "PASS"
action 4 = "DROP"
action 5 = "TRUNCATE"
action 6 = "LOCAL_DATA"
action _ = "UNKNOWN"

messageType :: Int -> String
messageType 1 = "AUTH_QUERY"
messageType 2 = "AUTH_RESPONSE"
messageType 3 = "RESOLVER_QUERY"
messageType 4 = "RESOLVER_RESPONSE"
messageType 5 = "CLIENT_QUERY"
messageType 6 = "CLIENT_RESPONSE"
messageType 7 = "FORWARDER_QUERY"
messageType 8 = "FORWARDER_RESPONSE"
messageType 9 = "STUB_QUERY"
messageType 10 = "STUB_RESPONSE"
messageType 11 = "TOOL_QUERY"
messageType 12 = "TOOL_RESPONSE"
messageType 13 = "UPDATE_QUERY"
messageType 14 = "UPDATE_RESPONSE"
messageType _ = "UNKNOWN"

----------------------------------------------------------------
-- Protocol buffer
-- https://protobuf.dev/programming-guides/encoding/

newtype WireType = WireType Int deriving Eq

pattern VARINT :: WireType
pattern VARINT = WireType 0
pattern I64 :: WireType
pattern I64 = WireType 1
pattern LEN :: WireType
pattern LEN = WireType 2
pattern I32 :: WireType
pattern I32 = WireType 5

instance Show WireType where
    show (WireType 0) = "VARINT"
    show (WireType 1) = "I64"
    show (WireType 2) = "LEN"
    show (WireType 5) = "I32"
    show (WireType x) = "WireType " ++ show x

varint :: Readable p => p -> IO Int
varint rbuf = loop 0 0
  where
    loop n0 s = do
        n <- fromIntegral <$> read8 rbuf
        let n1 = n0 + ((n .&. 0x7f) `shiftL` s)
        if n `testBit` 7
           then loop n1 (s + 7)
           else return n1

i32 :: Readable a => a -> IO Int
i32 rbuf = do
    n0 <- fromIntegral <$> read8 rbuf
    n1 <- fromIntegral <$> read8 rbuf
    n2 <- fromIntegral <$> read8 rbuf
    n3 <- fromIntegral <$> read8 rbuf
    return ((n3 `shiftL` 24) .|. (n2 `shiftL` 16) .|. (n1 `shiftL` 8) .|. n0)

tag :: Readable p => p -> IO (Int, WireType)
tag rbuf = do
    n <- varint rbuf
    let wtyp = n .&. 0x7
        num = n `shiftR` 3
    return (num, WireType wtyp)

skip :: Readable a1 => a1 -> WireType -> IO ()
skip rbuf VARINT = do
    len <- varint rbuf
    putStrLn $ "skipping VARINT " ++ show len
skip rbuf I64 = do
    _ <- read64 rbuf -- fixme endian
    putStrLn $ "skipping I64"
skip rbuf LEN = do
    len <- varint rbuf
    putStrLn $ "skipping LEN " ++ show len
    ff rbuf len
skip rbuf I32 = do
    _ <- i32 rbuf
    putStrLn $ "skipping I32"
skip rbuf _ = do
    putStrLn $ "skipping VARINT unknown"
    remainingSize rbuf >>= ff rbuf

dump :: Readable a => a -> IO ()
dump rbuf = do
    len <- varint rbuf
    bs <- extractByteString rbuf len
    C8.putStrLn $ B16.encode bs
