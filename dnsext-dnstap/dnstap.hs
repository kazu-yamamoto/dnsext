{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Main where

import Control.Concurrent
import Control.Monad
import Data.Bits
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Hexdump
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.BufferPool as P

-- Fast stream:
-- https://github.com/farsightsec/fstrm/blob/master/fstrm/control.h

-- DNSTAP
-- https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto

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
        putStrLn $ "fstrm data length: " ++ show l
        if l == 0
            then return ()
            else do
                bsx <- recvN l
--                putStrLn $ prettyHex bsx
                dnstap bsx
                loop

fstrmStop :: IO ()
fstrmStop = putStrLn "STOP"

dnstap :: ByteString -> IO ()
dnstap bsx = withReadBuffer bsx loop
  where
    loop rbuf = do
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
              putStr "Message "
              lenPref <- varint rbuf
              str <- extractByteString rbuf lenPref
              C8.putStrLn $ B16.encode str
          (15, VARINT) -> do
              putStr "Type "
              varint rbuf >>= print
          _ -> skip rbuf t
        rest <- remainingSize rbuf
        when (rest /= 0) $ loop rbuf

skip :: Readable a1 => a1 -> (Int, WireType) -> IO ()
skip rbuf (_,VARINT) = do
    len <- varint rbuf
    putStrLn $ "skipping VARINT " ++ show len
skip rbuf (_,I64) = do
    _ <- read64 rbuf -- fixme endian
    putStrLn $ "skipping I64"
skip rbuf (_,LEN) = do
    len <- varint rbuf
    putStrLn $ "skipping LEN " ++ show len
    ff rbuf len
skip rbuf (_,I32) = do
    _ <- read32 rbuf -- fixme endian
    putStrLn $ "skipping I64"
skip rbuf _ = do
    putStrLn $ "skipping VARINT uknown"
    remainingSize rbuf >>= ff rbuf


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

tag :: Readable p => p -> IO (Int, WireType)
tag rbuf = do
    n <- varint rbuf
    let wtyp = n .&. 0x7
        num = n `shiftR` 3
    return (num, WireType wtyp)
