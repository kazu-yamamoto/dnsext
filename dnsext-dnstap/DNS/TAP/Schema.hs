{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

-- | DNSTAP Schema.
--
-- * Spec: <https://github.com/dnstap/dnstap.pb/blob/master/dnstap.proto>
module DNS.TAP.Schema (
    -- * Types
    DNSTAP (..),
    defaultDNSTAP,
    DnstapType (MESSAGE),
    Message (..),
    TapMsg (..),
    defaultMessage,
    composeMessage,
    SocketFamily (IPv4, IPv6),
    SocketProtocol (UDP, TCP, DOT, DOH, DNSCryptUDP, DNSCryptTCP, DOQ),
    MessageType (
        AUTH_QUERY,
        AUTH_RESPONSE,
        RESOLVER_QUERY,
        RESOLVER_RESPONSE,
        CLIENT_QUERY,
        CLIENT_RESPONSE,
        FORWARDER_QUERY,
        FORWARDER_RESPONSE,
        STUB_QUERY,
        STUB_RESPONSE,
        TOOL_QUERY,
        TOOL_RESPONSE,
        UPDATE_QUERY,
        UPDATE_RESPONSE
    ),

    -- * Decoding
    decodeDnstap,
    decodeMessage,

    -- * Encoding
    encodeDnstap,
    encodeMessage,
) where

import DNS.Types (DNSError (..), DNSMessage)
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import qualified Data.ByteString as BS
import qualified Data.IP as IP
import Network.ByteOrder
import Network.Socket (SockAddr (..))

import DNS.TAP.ProtocolBuffer

{- FOURMOLU_DISABLE -}
data DNSTAP = DNSTAP
    { dnstapIdentity :: Maybe ByteString
    , dnstapVersion  :: Maybe ByteString
    , dnstapMessage  :: Maybe Message
    , dnstapType     :: DnstapType
    }
    deriving (Eq, Show)

defaultDNSTAP :: DNSTAP
defaultDNSTAP =
    DNSTAP
        { dnstapIdentity = Nothing
        , dnstapVersion  = Nothing
        , dnstapMessage  = Nothing
        , dnstapType     = MESSAGE
        }

decodeDnstap :: ByteString -> DNSTAP
decodeDnstap bs =
    DNSTAP
        { dnstapIdentity = getOptS obj 1 id
        , dnstapVersion  = getOptS obj 2 id
        , dnstapMessage  = decodeMessage <$> getOptS obj 14 id
        , dnstapType     = getI obj 15 DnstapType
        }
  where
    obj = decode bs

data TapMsg =
    DnsMsg DNSMessage
  | DecErr DNSError ByteString
  | WireFt ByteString
  deriving (Eq, Show)

data Message = Message
    { messageType             :: MessageType
    , messageSocketFamily     :: Maybe SocketFamily
    , messageSocketProtocol   :: Maybe SocketProtocol
    , messageQueryAddress     :: Maybe IP.IP
    , messageResponseAddress  :: Maybe IP.IP
    , messageQueryPort        :: Maybe Int
    , messageResponsePort     :: Maybe Int
    , messageQueryTimeSec     :: Maybe Int
    , messageQueryTimeNsec    :: Maybe Int
    , messageQueryMessage     :: Maybe TapMsg
    , messageQueryZone        :: Maybe ByteString
    , messageResponseTimeSec  :: Maybe Int
    , messageResponseTimeNsec :: Maybe Int
    , messageResponseMessage  :: Maybe TapMsg
    }
    deriving (Eq, Show)

defaultMessage :: Message
defaultMessage =
    Message
    { messageType             = CLIENT_RESPONSE
    , messageSocketFamily     = Nothing
    , messageSocketProtocol   = Nothing
    , messageQueryAddress     = Nothing
    , messageResponseAddress  = Nothing
    , messageQueryPort        = Nothing
    , messageResponsePort     = Nothing
    , messageQueryTimeSec     = Nothing
    , messageQueryTimeNsec    = Nothing
    , messageQueryMessage     = Nothing
    , messageQueryZone        = Nothing
    , messageResponseTimeSec  = Nothing
    , messageResponseTimeNsec = Nothing
    , messageResponseMessage  = Nothing
    }

composeMessage
    :: SocketProtocol
    -> Maybe SockAddr
    -> Maybe SockAddr
    -> DNS.EpochTime
    -> ByteString
    -> Message
composeMessage proto mysa peersa t bs =
    defaultMessage
        { messageSocketFamily    = peersa >>= toFamily
        , messageSocketProtocol  = Just proto
        , messageQueryAddress    = peersa >>= toIP
        , messageResponseAddress = mysa >>= toIP
        , messageQueryPort       = peersa >>= toPort
        , messageResponsePort    = mysa >>= toPort
        , messageResponseTimeSec = Just $ fromIntegral t
        , messageResponseMessage = Just $ WireFt bs
        }
 where
   toFamily sa = case sa of
     SockAddrInet{}  -> Just IPv4
     SockAddrInet6{} -> Just IPv6
     _               -> Nothing
   toPort sa = case sa of
     SockAddrInet  p _     -> Just $ fromIntegral p
     SockAddrInet6 p _ _ _ -> Just $ fromIntegral p
     _                     -> Nothing
   toIP sa = fst <$> IP.fromSockAddr sa

decodeMessage :: ByteString -> Message
decodeMessage bs =
    Message
        { messageType             = getI    obj  1 MessageType
        , messageSocketFamily     = getOptI obj  2 SocketFamily
        , messageSocketProtocol   = getOptI obj  3 SocketProtocol
        , messageQueryAddress     = getOptS obj  4 decodeIP
        , messageResponseAddress  = getOptS obj  5 decodeIP
        , messageQueryPort        = getOptI obj  6 id
        , messageResponsePort     = getOptI obj  7 id
        , messageQueryTimeSec     = getOptI obj  8 id
        , messageQueryTimeNsec    = getOptI obj  9 id
        , messageQueryMessage     = getOptS obj 10 decodeDNS
        , messageQueryZone        = getOptS obj 11 id
        , messageResponseTimeSec  = getOptI obj 12 id
        , messageResponseTimeNsec = getOptI obj 13 id
        , messageResponseMessage  = getOptS obj 14 decodeDNS
        }
  where
    obj = decode bs

decodeDNS :: ByteString -> TapMsg
decodeDNS bs = case DNS.decode bs of
  Right msg -> DnsMsg msg
  Left err  -> DecErr err bs

decodeIP :: ByteString -> IP.IP
decodeIP bs
  | BS.length bs == 4 = IP.IPv4 $ IP.toIPv4  $ map fromIntegral $ BS.unpack bs
  | otherwise         = IP.IPv6 $ IP.toIPv6b $ map fromIntegral $ BS.unpack bs

----------------------------------------------------------------

encodeDnstap :: DNSTAP -> ByteString
encodeDnstap DNSTAP{..} = encode $
    setVAR  15 (fromDnstapType dnstapType) $
    setOptS 14 (encodeMessage <$> dnstapMessage) $
    setOptS  2 dnstapVersion $
    setOptS  1 dnstapIdentity empty

encodeMessage :: Message -> ByteString
encodeMessage Message{..} = encode $
    setOptS   14 (encodeDNS <$> messageResponseMessage) $
    setOptI32 13 messageResponseTimeNsec $
    setOptI64 12 messageResponseTimeSec $
    setOptS   11 messageQueryZone $
    setOptS   10 (encodeDNS <$> messageQueryMessage) $
    setOptI32  9 messageQueryTimeNsec $
    setOptI64  8 messageQueryTimeSec $
    setOptI32  7 messageResponsePort $
    setOptI32  6 messageQueryPort $
    setOptS    5 (encodeIP <$> messageResponseAddress) $
    setOptS    4 (encodeIP <$> messageQueryAddress) $
    setOptVAR  3 (fromSocketProtocol <$> messageSocketProtocol) $
    setOptVAR  2 (fromSocketFamily <$> messageSocketFamily) $
    setVAR     1 (fromMessageType messageType) empty

encodeDNS :: TapMsg -> ByteString
encodeDNS (DnsMsg msg)  = DNS.encode msg
encodeDNS (DecErr _ bs) = bs
encodeDNS (WireFt bs)   = bs

encodeIP :: IP.IP -> ByteString
encodeIP (IP.IPv4 ip) = BS.pack $ map fromIntegral $ IP.fromIPv4 ip
encodeIP (IP.IPv6 ip) = BS.pack $ map fromIntegral $ IP.fromIPv6b ip

----------------------------------------------------------------

newtype DnstapType = DnstapType { fromDnstapType :: Int } deriving Eq

pattern MESSAGE :: DnstapType
pattern MESSAGE  = DnstapType 1

instance Show DnstapType where
    show MESSAGE        = "MESSAGE"
    show (DnstapType x) = "DnstapType " ++ show x

----------------------------------------------------------------

newtype SocketFamily = SocketFamily { fromSocketFamily :: Int } deriving Eq

pattern IPv4 :: SocketFamily
pattern IPv4  = SocketFamily 1
pattern IPv6 :: SocketFamily
pattern IPv6  = SocketFamily 2

instance Show SocketFamily where
    show IPv4 = "IPv4"
    show IPv6 = "IPv6"
    show (SocketFamily x) = "SocketFamily " ++ show x

----------------------------------------------------------------

newtype SocketProtocol = SocketProtocol { fromSocketProtocol :: Int } deriving Eq

pattern UDP         :: SocketProtocol
pattern UDP          = SocketProtocol 1
pattern TCP         :: SocketProtocol
pattern TCP          = SocketProtocol 2
pattern DOT         :: SocketProtocol
pattern DOT          = SocketProtocol 3
pattern DOH         :: SocketProtocol
pattern DOH          = SocketProtocol 4
pattern DNSCryptUDP :: SocketProtocol
pattern DNSCryptUDP  = SocketProtocol 5
pattern DNSCryptTCP :: SocketProtocol
pattern DNSCryptTCP  = SocketProtocol 6
pattern DOQ         :: SocketProtocol
pattern DOQ          = SocketProtocol 7

instance Show SocketProtocol where
    show UDP                = "UDP"
    show TCP                = "TCP"
    show DOT                = "DOT"
    show DOH                = "DOH"
    show DNSCryptUDP        = "DNSCryptUDP"
    show DNSCryptTCP        = "DNSCryptTCP"
    show DOQ                = "DOQ"
    show (SocketProtocol x) = "SocketProtocol " ++ show x

----------------------------------------------------------------

newtype MessageType = MessageType { fromMessageType :: Int } deriving Eq

pattern AUTH_QUERY         :: MessageType
pattern AUTH_QUERY          = MessageType  1
pattern AUTH_RESPONSE      :: MessageType
pattern AUTH_RESPONSE       = MessageType  2
pattern RESOLVER_QUERY     :: MessageType
pattern RESOLVER_QUERY      = MessageType  3
pattern RESOLVER_RESPONSE  :: MessageType
pattern RESOLVER_RESPONSE   = MessageType  4
pattern CLIENT_QUERY       :: MessageType
pattern CLIENT_QUERY        = MessageType  5
pattern CLIENT_RESPONSE    :: MessageType
pattern CLIENT_RESPONSE     = MessageType  6
pattern FORWARDER_QUERY    :: MessageType
pattern FORWARDER_QUERY     = MessageType  7
pattern FORWARDER_RESPONSE :: MessageType
pattern FORWARDER_RESPONSE  = MessageType  8
pattern STUB_QUERY         :: MessageType
pattern STUB_QUERY          = MessageType  9
pattern STUB_RESPONSE      :: MessageType
pattern STUB_RESPONSE       = MessageType 10
pattern TOOL_QUERY         :: MessageType
pattern TOOL_QUERY          = MessageType 11
pattern TOOL_RESPONSE      :: MessageType
pattern TOOL_RESPONSE       = MessageType 12
pattern UPDATE_QUERY       :: MessageType
pattern UPDATE_QUERY        = MessageType 13
pattern UPDATE_RESPONSE    :: MessageType
pattern UPDATE_RESPONSE     = MessageType 14

instance Show MessageType where
    show AUTH_QUERY         = "AUTH_QUERY"
    show AUTH_RESPONSE      = "AUTH_RESPONSE"
    show RESOLVER_QUERY     = "RESOLVER_QUERY"
    show RESOLVER_RESPONSE  = "RESOLVER_RESPONSE"
    show CLIENT_QUERY       = "CLIENT_QUERY"
    show CLIENT_RESPONSE    = "CLIENT_RESPONSE"
    show FORWARDER_QUERY    = "FORWARDER_QUERY"
    show FORWARDER_RESPONSE = "FORWARDER_RESPONSE"
    show STUB_QUERY         = "STUB_QUERY"
    show STUB_RESPONSE      = "STUB_RESPONSE"
    show TOOL_QUERY         = "TOOL_QUERY"
    show TOOL_RESPONSE      = "TOOL_RESPONSE"
    show UPDATE_QUERY       = "UPDATE_QUERY"
    show UPDATE_RESPONSE    = "UPDATE_RESPONSE"
    show (MessageType  x)   = "MessageType " ++ show x

{- FOURMOLU_ENABLE -}
