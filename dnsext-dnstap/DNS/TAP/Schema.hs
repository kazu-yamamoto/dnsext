-- | DNSTAP Schema.
--
-- * Spec: https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto
module DNS.TAP.Schema (
    dnstap,
    DNSTAP (..),
    Message (..),
) where

import DNS.Types (DNSMessage)
import qualified DNS.Types.Decode as DNS
import Network.ByteOrder

import DNS.TAP.ProtocolBuffer

data DNSTAP = DNSTAP
    { dnstapIdentity :: Maybe ByteString
    , dnstapVresion :: Maybe ByteString
    , dnstapMessage :: Message
    , dnstapType :: String
    }
    deriving (Eq, Show)

dnstap :: ByteString -> IO DNSTAP
dnstap bs = do
    obj <- decode bs
    msg <- message (getS obj 14 id)
    return
        DNSTAP
            { dnstapIdentity = getSm obj 1 id
            , dnstapVresion = getSm obj 2 id
            , dnstapMessage = msg
            , dnstapType = getI obj 15 dnstapType'
            }

data Message = Message
    { messageType :: String
    , messageSocketFamily :: Maybe String
    , messageSocketProtocol :: Maybe String
    , messageQueryAddress :: Maybe ByteString -- fixme
    , messageResponseAddress :: Maybe ByteString -- fixme
    , messageQueryPort :: Maybe Int
    , messageResponsePort :: Maybe Int
    , messageQueryTimeSec :: Maybe Int
    , messageQueryTimeNsec :: Maybe Int
    , messageQueryMessage :: Maybe DNSMessage
    , messageQueryZone :: Maybe ByteString
    , messageResponseTimeSec :: Maybe Int
    , messageResponseTimeNsec :: Maybe Int
    , messageResponseMessage :: Maybe DNSMessage
    }
    deriving (Eq, Show)

message :: ByteString -> IO Message
message bs = do
    obj <- decode bs
    return
        Message
            { messageType = getI obj 1 messageType'
            , messageSocketFamily = getIm obj 2 socketFamily
            , messageSocketProtocol = getIm obj 3 socketProtocol
            , messageQueryAddress = getSm obj 4 id
            , messageResponseAddress = getSm obj 5 id
            , messageQueryPort = getIm obj 6 id
            , messageResponsePort = getIm obj 7 id
            , messageQueryTimeSec = getIm obj 8 id
            , messageQueryTimeNsec = getIm obj 9 id
            , messageQueryMessage = getSm obj 10 decodeDNSMessage
            , messageQueryZone = getSm obj 11 id
            , messageResponseTimeSec = getIm obj 12 id
            , messageResponseTimeNsec = getIm obj 13 id
            , messageResponseMessage = getSm obj 14 decodeDNSMessage
            }

----------------------------------------------------------------

decodeDNSMessage :: ByteString -> DNSMessage
decodeDNSMessage bs = case DNS.decode bs of
    Right x -> x
    Left e -> error (show e)

----------------------------------------------------------------
-- enum

dnstapType' :: Int -> String
dnstapType' 1 = "MESSAGE"
dnstapType' _ = "UNKNOWN"

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

messageType' :: Int -> String
messageType' 1 = "AUTH_QUERY"
messageType' 2 = "AUTH_RESPONSE"
messageType' 3 = "RESOLVER_QUERY"
messageType' 4 = "RESOLVER_RESPONSE"
messageType' 5 = "CLIENT_QUERY"
messageType' 6 = "CLIENT_RESPONSE"
messageType' 7 = "FORWARDER_QUERY"
messageType' 8 = "FORWARDER_RESPONSE"
messageType' 9 = "STUB_QUERY"
messageType' 10 = "STUB_RESPONSE"
messageType' 11 = "TOOL_QUERY"
messageType' 12 = "TOOL_RESPONSE"
messageType' 13 = "UPDATE_QUERY"
messageType' 14 = "UPDATE_RESPONSE"
messageType' _ = "UNKNOWN"
