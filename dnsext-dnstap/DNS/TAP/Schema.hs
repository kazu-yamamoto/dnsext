-- | DNSTAP Schema.
--
-- * Spec: https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto
module DNS.TAP.Schema (
    -- * Types
    DNSTAP (..),
    Message (..),
    -- * Decoding
    decodeDnstap,
    decodeMessage,
) where

import DNS.Types (DNSMessage, DNSError)
import qualified DNS.Types.Decode as DNS
import qualified Data.ByteString as BS
import Data.IP
import Network.ByteOrder

import DNS.TAP.ProtocolBuffer

{- FOURMOLU_DISABLE -}
data DNSTAP = DNSTAP
    { dnstapIdentity :: Maybe ByteString
    , dnstapVresion  :: Maybe ByteString
    , dnstapMessage  :: Maybe Message
    , dnstapType     :: String
    }
    deriving (Eq, Show)

decodeDnstap :: ByteString -> DNSTAP
decodeDnstap bs =
    DNSTAP
        { dnstapIdentity = getOptS obj 1 id
        , dnstapVresion  = getOptS obj 2 id
        , dnstapMessage  = decodeMessage <$> getOptS obj 14 id
        , dnstapType     = getI obj 15 dnstapType'
        }
  where
    obj = decode bs

data Message = Message
    { messageType             :: String
    , messageSocketFamily     :: Maybe String
    , messageSocketProtocol   :: Maybe String
    , messageQueryAddress     :: Maybe IP
    , messageResponseAddress  :: Maybe IP
    , messageQueryPort        :: Maybe Int
    , messageResponsePort     :: Maybe Int
    , messageQueryTimeSec     :: Maybe Int
    , messageQueryTimeNsec    :: Maybe Int
    , messageQueryMessage     :: Maybe (Either DNSError DNSMessage)
    , messageQueryZone        :: Maybe ByteString
    , messageResponseTimeSec  :: Maybe Int
    , messageResponseTimeNsec :: Maybe Int
    , messageResponseMessage  :: Maybe (Either DNSError DNSMessage)
    }
    deriving (Eq, Show)

decodeMessage :: ByteString -> Message
decodeMessage bs =
    Message
        { messageType             = getI    obj  1 messageType'
        , messageSocketFamily     = getOptI obj  2 socketFamily
        , messageSocketProtocol   = getOptI obj  3 socketProtocol
        , messageQueryAddress     = getOptS obj  4 ip
        , messageResponseAddress  = getOptS obj  5 ip
        , messageQueryPort        = getOptI obj  6 id
        , messageResponsePort     = getOptI obj  7 id
        , messageQueryTimeSec     = getOptI obj  8 id
        , messageQueryTimeNsec    = getOptI obj  9 id
        , messageQueryMessage     = getOptS obj 10 DNS.decode
        , messageQueryZone        = getOptS obj 11 id
        , messageResponseTimeSec  = getOptI obj 12 id
        , messageResponseTimeNsec = getOptI obj 13 id
        , messageResponseMessage  = getOptS obj 14 DNS.decode
        }
  where
    obj = decode bs

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
messageType'  1 = "AUTH_QUERY"
messageType'  2 = "AUTH_RESPONSE"
messageType'  3 = "RESOLVER_QUERY"
messageType'  4 = "RESOLVER_RESPONSE"
messageType'  5 = "CLIENT_QUERY"
messageType'  6 = "CLIENT_RESPONSE"
messageType'  7 = "FORWARDER_QUERY"
messageType'  8 = "FORWARDER_RESPONSE"
messageType'  9 = "STUB_QUERY"
messageType' 10 = "STUB_RESPONSE"
messageType' 11 = "TOOL_QUERY"
messageType' 12 = "TOOL_RESPONSE"
messageType' 13 = "UPDATE_QUERY"
messageType' 14 = "UPDATE_RESPONSE"
messageType' _  = "UNKNOWN"

ip :: ByteString -> IP
ip bs
  | BS.length bs == 4 = IPv4 $ toIPv4  $ map fromIntegral $ BS.unpack bs
  | otherwise         = IPv6 $ toIPv6b $ map fromIntegral $ BS.unpack bs
{- FOURMOLU_ENABLE -}
