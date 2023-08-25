-- | DNSTAP Schema.
--
-- * Spec: https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto
module DNS.TAP.Schema (dnstap) where

import Control.Monad
import DNS.Types.Decode
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Network.ByteOrder

import DNS.TAP.ProtocolBuffer

dnstap :: ByteString -> IO ()
dnstap bsx = withReadBuffer bsx loop
  where
    loop rbuf = do
        putStr "DNSTAP "
        t <- tag rbuf
        case t of
            (1, LEN) -> do
                putStr "Identity: "
                dumpASCII rbuf
            (2, LEN) -> do
                putStr "Version: "
                dumpASCII rbuf
            (14, LEN) -> do
                putStrLn "Message:"
                lenPref <- varint rbuf
                bs <- extractByteString rbuf lenPref
                message bs
            (15, VARINT) -> do
                putStr "Type: "
                varint rbuf >>= putStrLn . dnstapType
            (num, wt) -> do
                putStr $ "KEY: " ++ show num ++ " "
                skip rbuf wt
        rest <- remainingSize rbuf
        when (rest /= 0) $ loop rbuf

message :: ByteString -> IO ()
message bs = withReadBuffer bs loop
  where
    loop rbuf = do
        putStr "Message "
        t <- tag rbuf
        case t of
            (1, VARINT) -> do
                putStr "Type: "
                varint rbuf >>= putStrLn . messageType
            (2, VARINT) -> do
                putStr "SocketFamily: "
                varint rbuf >>= putStrLn . socketFamily
            (3, VARINT) -> do
                putStr "SocketProtocol: "
                varint rbuf >>= putStrLn . socketProtocol
            (4, LEN) -> do
                putStr "QueryAddress: "
                dump rbuf
            (5, LEN) -> do
                putStr "ResponseAddress: "
                dump rbuf
            (6, VARINT) -> do
                putStr "QueryPort: "
                varint rbuf >>= print
            (7, VARINT) -> do
                putStr "ResponsePort: "
                varint rbuf >>= print
            (8, VARINT) -> do
                putStr "QueryTimeSec: "
                varint rbuf >>= print
            (9, I32) -> do
                putStr "QueryTimeNsec: "
                i32 rbuf >>= print
            (10, LEN) -> do
                putStr "QueryMessage: "
                decodeDNSMessage rbuf
            (11, LEN) -> do
                putStr "QueryZone: "
                dump rbuf
            (12, VARINT) -> do
                putStr "ResponseTimeSec: "
                varint rbuf >>= print
            (13, I32) -> do
                putStr "ResponseTimeNsec: "
                i32 rbuf >>= print
            (14, LEN) -> do
                putStr "ResponseMessage: "
                decodeDNSMessage rbuf
            (15, LEN) -> do
                lenPref <- varint rbuf
                bs' <- extractByteString rbuf lenPref
                policy bs'
            (num, wt) -> do
                putStr $ "KEY: " ++ show num ++ " "
                skip rbuf wt
        rest <- remainingSize rbuf
        when (rest /= 0) $ loop rbuf

policy :: ByteString -> IO ()
policy bs = withReadBuffer bs loop
  where
    loop rbuf = do
        putStr "POLICY "
        t <- tag rbuf
        case t of
            -- fixme
            (3, VARINT) -> do
                putStr "Action: "
                varint rbuf >>= putStrLn . action
            (4, VARINT) -> do
                putStr "Match: "
                varint rbuf >>= putStrLn . match
            (5, LEN) -> do
                putStr "Value "
                dump rbuf
            (num, wt) -> do
                putStr $ "KEY " ++ show num ++ " "
                skip rbuf wt

----------------------------------------------------------------

decodeDNSMessage :: Readable a => a -> IO ()
decodeDNSMessage rbuf = do
    len <- varint rbuf
    bs <- extractByteString rbuf len
    case decode bs of
        Right x -> print x
        Left e -> do
            print e
            C8.putStrLn $ B16.encode bs

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
