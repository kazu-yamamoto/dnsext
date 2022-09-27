{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE PatternSynonyms #-}

module DNS.Types.EDNS (
    EDNS(..)
  , defaultEDNS
  , maxUdpSize
  , minUdpSize
  , OptCode (
    NSID
  , DAU
  , DHU
  , N3U
  , ClientSubnet
  )
  , fromOptCode
  , toOptCode
  , odataToOptCode
  , OptData(..)
  , fromOData
  , toOData
  , encodeOData
  , OData(..)
  , OD_NSID(..)
  , OD_DAU(..)
  , OD_DHU(..)
  , OD_N3U(..)
  , OD_ClientSubnet(..)
  , od_nsid
  , od_dau
  , od_dhu
  , od_n3u
  , od_clientSubnet
  , od_ecsGeneric
  , od_unknown
  ) where

import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import Data.IP (IP(..), fromIPv4, toIPv4, fromIPv6b, toIPv6b, makeAddrRange)
import qualified Data.IP (addr)

import DNS.StateBinary
import DNS.Types.Imports
import DNS.Types.Opaque

----------------------------------------------------------------
-- EDNS (RFC 6891, EDNS(0))
----------------------------------------------------------------

-- | EDNS information defined in RFC 6891.
data EDNS = EDNS {
    -- | EDNS version, presently only version 0 is defined.
    ednsVersion  :: Word8
    -- | Supported UDP payload size.
  , ednsUdpSize  :: Word16
    -- | Request DNSSEC replies (with RRSIG and NSEC records as as appropriate)
    -- from the server.  Generally, not needed (except for diagnostic purposes)
    -- unless the signatures will be validated.  Just setting the 'AD' bit in
    -- the query and checking it in the response is sufficient (but often
    -- subject to man-in-the-middle forgery) if all that's wanted is whether
    -- the server validated the response.
  , ednsDnssecOk :: Bool
    -- | EDNS options (e.g. 'OD_NSID', 'OD_ClientSubnet', ...)
  , ednsOptions  :: [OData]
  } deriving (Eq, Show)

-- | The default EDNS pseudo-header for queries.  The UDP buffer size is set to
--   1216 bytes, which should result in replies that fit into the 1280 byte
--   IPv6 minimum MTU.  Since IPv6 only supports fragmentation at the source,
--   and even then not all gateways forward IPv6 pre-fragmented IPv6 packets,
--   it is best to keep DNS packet sizes below this limit when using IPv6
--   nameservers.  A larger value may be practical when using IPv4 exclusively.
--
-- @
-- defaultEDNS = EDNS
--     { ednsVersion = 0      -- The default EDNS version is 0
--     , ednsUdpSize = 1232   -- IPv6-safe UDP MTU (RIPE recommendation)
--     , ednsDnssecOk = False -- We don't do DNSSEC validation
--     , ednsOptions = []     -- No EDNS options by default
--     }
-- @
--
defaultEDNS :: EDNS
defaultEDNS = EDNS
    { ednsVersion = 0      -- The default EDNS version is 0
    , ednsUdpSize = 1232   -- IPv6-safe UDP MTU
    , ednsDnssecOk = False -- We don't do DNSSEC validation
    , ednsOptions = []     -- No EDNS options by default
    }

-- | Maximum UDP size that can be advertised.  If the 'ednsUdpSize' of 'EDNS'
--   is larger, then this value is sent instead.  This value is likely to work
--   only for local nameservers on the loopback network.  Servers may enforce
--   a smaller limit.
--
-- >>> maxUdpSize
-- 16384
maxUdpSize :: Word16
maxUdpSize = 16384

-- | Minimum UDP size to advertise. If 'ednsUdpSize' of 'EDNS' is smaller,
--   then this value is sent instead.
--
-- >>> minUdpSize
-- 512
minUdpSize :: Word16
minUdpSize = 512

----------------------------------------------------------------

-- | EDNS Option Code (RFC 6891).
newtype OptCode = OptCode {
    -- | From option code to number.
    fromOptCode :: Word16
  } deriving (Eq,Ord)

-- | NSID (RFC5001, section 2.3)
pattern NSID :: OptCode
pattern NSID  = OptCode 3

-- | DNSSEC algorithm support (RFC6975, section 3)
pattern DAU  :: OptCode
pattern DAU   = OptCode 5
pattern DHU  :: OptCode
pattern DHU   = OptCode 6
pattern N3U  :: OptCode
pattern N3U   = OptCode 7

-- | Client subnet (RFC7871)
pattern ClientSubnet :: OptCode
pattern ClientSubnet = OptCode 8

instance Show OptCode where
    show NSID         = "NSID"
    show DAU          = "DAU"
    show DHU          = "DHU"
    show N3U          = "N3U"
    show ClientSubnet = "ClientSubnet"
    show (OptCode n)  = "OptCode " ++ show n

-- | From number to option code.
toOptCode :: Word16 -> OptCode
toOptCode = OptCode

---------------------------------------------------------------

class (Typeable a, Eq a, Show a) => OptData a where
    optDataCode   :: a -> OptCode
    encodeOptData :: a -> SPut
    decodeOptData :: proxy a -> Int -> SGet a

---------------------------------------------------------------

-- | A type to uniform 'OptData' 'a'.
data OData = forall a . (Typeable a, Eq a, Show a, OptData a) => OData a

-- | Extracting the original type.
fromOData :: Typeable a => OData -> Maybe a
fromOData (OData x) = cast x

-- | Wrapping the original type with 'OData'.
toOData :: (Typeable a, OptData a) => a -> OData
toOData = OData

instance Show OData where
    show (OData x) = show x

instance Eq OData where
    x@(OData xi) == y@(OData yi) = typeOf x == typeOf y && Just xi == cast yi

-- | Getting 'OptCode' of 'OData'.
odataToOptCode :: OData -> OptCode
odataToOptCode (OData x) = optDataCode x

encodeOData :: OData -> SPut
encodeOData (OData x) = encodeOptData x

---------------------------------------------------------------

-- | Name Server Identifier (RFC5001).  Bidirectional, empty from client.
-- (opaque octet-string).  May contain binary data, which MUST be empty
-- in queries.
newtype OD_NSID = OD_NSID Opaque deriving (Eq)

instance Show OD_NSID where
    show = _showNSID

instance OptData OD_NSID where
    optDataCode _ = NSID
    encodeOptData (OD_NSID nsid) = putODBytes (fromOptCode NSID) nsid
    decodeOptData _ len = OD_NSID . shortByteStringToOpaque <$> getNShortByteString len

od_nsid :: Opaque -> OData
od_nsid = toOData . OD_NSID

---------------------------------------------------------------

-- | DNSSEC Algorithm Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported DNSKEY algorithms.
newtype OD_DAU = OD_DAU [Word8] deriving (Eq)

instance Show OD_DAU where
    show (OD_DAU as) = _showAlgList "DAU" as

instance OptData OD_DAU where
    optDataCode _ = DAU
    encodeOptData (OD_DAU as) = putODWords (fromOptCode DAU) as
    decodeOptData _ len = OD_DAU <$> getNOctets len

od_dau :: [Word8] -> OData
od_dau a = toOData $ OD_DAU a

---------------------------------------------------------------

-- | DS Hash Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported DS hash algorithms.
newtype OD_DHU = OD_DHU [Word8] deriving (Eq)

instance Show OD_DHU where
    show (OD_DHU hs)    = _showAlgList "DHU" hs

instance OptData OD_DHU where
    optDataCode _ = DHU
    encodeOptData (OD_DHU hs) = putODWords (fromOptCode DHU) hs
    decodeOptData _ len = OD_DHU <$> getNOctets len

od_dhu :: [Word8] -> OData
od_dhu a = toOData $ OD_DHU a

---------------------------------------------------------------

-- | NSEC3 Hash Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported NSEC3 hash algorithms.
newtype OD_N3U = OD_N3U [Word8] deriving (Eq)

instance Show OD_N3U where
    show (OD_N3U hs)    = _showAlgList "N3U" hs

instance OptData OD_N3U where
    optDataCode _ = N3U
    encodeOptData (OD_N3U hs) = putODWords (fromOptCode N3U) hs
    decodeOptData _ len = OD_N3U <$> getNOctets len

od_n3u :: [Word8] -> OData
od_n3u a = toOData $ OD_N3U a

---------------------------------------------------------------

-- | ECS(EDNS client subnet) (RFC7871).
data OD_ClientSubnet =
  -- | Valid client subnet.
  --   Bidirectional. (source bits, scope bits, address).
  --   The address is masked and truncated when encoding queries.
  --   The address is zero-padded when decoding.
    OD_ClientSubnet Word8 Word8 IP
  -- | Unsupported or malformed IP client subnet option.  Bidirectional.
  --   (address family, source bits, scope bits, opaque address).
    | OD_ECSgeneric Word16 Word8 Word8 Opaque
                     deriving (Eq)

instance Show OD_ClientSubnet where
    show (OD_ClientSubnet b1 b2 ip@(IPv4 _)) = _showECS 1 b1 b2 $ show ip
    show (OD_ClientSubnet b1 b2 ip@(IPv6 _)) = _showECS 2 b1 b2 $ show ip
    show (OD_ECSgeneric fam b1 b2 a) = _showECS fam b1 b2 $ b16encode $ opaqueToByteString a

instance OptData OD_ClientSubnet where
    optDataCode _ = ClientSubnet
    encodeOptData = encodeClientSubnet
    decodeOptData _ len = decodeClientSubnet len

encodeClientSubnet :: OD_ClientSubnet -> SPut
encodeClientSubnet (OD_ClientSubnet srcBits scpBits ip) =
    -- https://tools.ietf.org/html/rfc7871#section-6
    --
    -- o  ADDRESS, variable number of octets, contains either an IPv4 or
    --    IPv6 address, depending on FAMILY, which MUST be truncated to the
    --    number of bits indicated by the SOURCE PREFIX-LENGTH field,
    --    padding with 0 bits to pad to the end of the last octet needed.
    --
    -- o  A server receiving an ECS option that uses either too few or too
    --    many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
    --    SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
    --    as a signal to the software developer making the request to fix
    --    their implementation.
    --
    let octets = fromIntegral $ (srcBits + 7) `div` 8
        prefix addr = Data.IP.addr $ makeAddrRange addr $ fromIntegral srcBits
        (family, raw) = case ip of
                        IPv4 ip4 -> (1, take octets $ fromIPv4  $ prefix ip4)
                        IPv6 ip6 -> (2, take octets $ fromIPv6b $ prefix ip6)
        dataLen = 2 + 2 + octets
     in mconcat [ put16 $ fromOptCode ClientSubnet
                , putInt16 dataLen
                , put16 family
                , put8 srcBits
                , put8 scpBits
                , mconcat $ fmap putInt8 raw
                ]
encodeClientSubnet (OD_ECSgeneric family srcBits scpBits addr) =
    mconcat [ put16 $ fromOptCode ClientSubnet
            , putInt16 $ 4 + len
            , put16 family
            , put8 srcBits
            , put8 scpBits
            , putShortByteString sbs
            ]
  where
     sbs = opaqueToShortByteString addr
     len = Short.length sbs

decodeClientSubnet :: Int -> SGet OD_ClientSubnet
decodeClientSubnet len = do
        family  <- get16
        srcBits <- get8
        scpBits <- get8
        addr    <- getOpaque (len - 4) -- 4 = 2 + 1 + 1
        --
        -- https://tools.ietf.org/html/rfc7871#section-6
        --
        -- o  ADDRESS, variable number of octets, contains either an IPv4 or
        --    IPv6 address, depending on FAMILY, which MUST be truncated to the
        --    number of bits indicated by the SOURCE PREFIX-LENGTH field,
        --    padding with 0 bits to pad to the end of the last octet needed.
        --
        -- o  A server receiving an ECS option that uses either too few or too
        --    many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
        --    SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
        --    as a signal to the software developer making the request to fix
        --    their implementation.
        --
        -- In order to avoid needless decoding errors, when the ECS encoding
        -- requirements are violated, we construct an OD_ECSgeneric OData,
        -- instread of an IP-specific OD_ClientSubnet OData, which will only
        -- be used for valid inputs.  When the family is neither IPv4(1) nor
        -- IPv6(2), or the address prefix is not correctly encoded (too long
        -- or too short), the OD_ECSgeneric data contains the verbatim input
        -- from the peer.
        --
        let addrbs = opaqueToShortByteString addr
        case Short.length addrbs == (fromIntegral srcBits + 7) `div` 8 of
            True | Just ip <- bstoip family addrbs srcBits scpBits
                -> pure $ OD_ClientSubnet srcBits scpBits ip
            _   -> pure $ OD_ECSgeneric family srcBits scpBits addr
  where
    prefix addr bits = Data.IP.addr $ makeAddrRange addr $ fromIntegral bits
    zeropad = (++ repeat 0) . map fromIntegral . Short.unpack
    checkBits fromBytes toIP srcBits scpBits bytes =
        let addr       = fromBytes bytes
            maskedAddr = prefix addr srcBits
            maxBits    = fromIntegral $ 8 * length bytes
         in if addr == maskedAddr && scpBits <= maxBits
            then Just $ toIP addr
            else Nothing
    bstoip :: Word16 -> ShortByteString -> Word8 -> Word8 -> Maybe IP
    bstoip family bs srcBits scpBits = case family of
        1 -> checkBits toIPv4  IPv4 srcBits scpBits $ take 4  $ zeropad bs
        2 -> checkBits toIPv6b IPv6 srcBits scpBits $ take 16 $ zeropad bs
        _ -> Nothing

od_clientSubnet :: Word8 -> Word8 -> IP -> OData
od_clientSubnet a b c = toOData $ OD_ClientSubnet a b c

od_ecsGeneric :: Word16 -> Word8 -> Word8 -> Opaque -> OData
od_ecsGeneric a b c d = toOData $ OD_ECSgeneric a b c d

---------------------------------------------------------------

-- | Generic EDNS option.
-- (numeric 'OptCode', opaque content)
data OD_Unknown = OD_Unknown Word16 Opaque deriving (Eq)

instance Show OD_Unknown where
    show (OD_Unknown code o) =
        "OD_Unknown " ++ show code ++ " " ++ show o

instance OptData OD_Unknown where
    optDataCode (OD_Unknown n _) = toOptCode n
    encodeOptData (OD_Unknown code bs) = putODBytes code bs
    decodeOptData = undefined -- never used

od_unknown :: Word16 -> Opaque -> OData
od_unknown code o = toOData $ OD_Unknown code o

---------------------------------------------------------------

_showAlgList :: String -> [Word8] -> String
_showAlgList nm ws = nm ++ " " ++ intercalate "," (map show ws)

_showNSID :: OD_NSID -> String
_showNSID (OD_NSID nsid) = "NSID "
                        ++ b16encode bs
                        ++ ";"
                        ++ printable bs
  where
    bs = opaqueToByteString nsid
    printable = map (\c -> if c < ' ' || c > '~' then '?' else c) . C8.unpack

_showECS :: Word16 -> Word8 -> Word8 -> String -> String
_showECS family srcBits scpBits address =
    show family ++ " " ++ show srcBits
                ++ " " ++ show scpBits ++ " " ++ address

---------------------------------------------------------------

-- | Encode EDNS OPTION consisting of a list of octets.
putODWords :: Word16 -> [Word8] -> SPut
putODWords code ws =
     mconcat [ put16 code
             , putInt16 $ length ws
             , mconcat $ map put8 ws
             ]

-- | Encode an EDNS OPTION byte string.
putODBytes :: Word16 -> Opaque -> SPut
putODBytes code o =
    mconcat [ put16 code
            , putInt16 len
            , putShortByteString sbs
            ]
  where
    sbs = opaqueToShortByteString o
    len = Short.length sbs
