{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Types.RData where

import qualified Data.Text as T
import Data.Char (intToDigit, ord)
import Data.IP (IPv4, IPv6, fromIPv4, toIPv4, fromIPv6b, toIPv6b)

import DNS.StateBinary
import DNS.Types.Domain
import DNS.Types.EDNS
import DNS.Types.Imports
import DNS.Types.Opaque
import DNS.Types.Type

---------------------------------------------------------------

class (Typeable a, Eq a, Show a) => ResourceData a where
    resourceDataType :: a -> TYPE
    putResourceData  :: a -> SPut
    getResourceData  :: proxy a -> Int -> SGet a

---------------------------------------------------------------

-- | A type to uniform 'ResourceData' 'a'.
data RData = forall a . (Typeable a, Eq a, Show a, ResourceData a) => RData a

-- | Extracting the original type.
fromRData :: Typeable a => RData -> Maybe a
fromRData (RData x) = cast x

-- | Wrapping the original type with 'RData'.
toRData :: (Typeable a, ResourceData a) => a -> RData
toRData = RData

instance Show RData where
    show (RData x) = show x

instance Eq RData where
    x@(RData xi) == y@(RData yi) = typeOf x == typeOf y && Just xi == cast yi

-- | Getting 'TYPE' of 'RData'.
rdataType :: RData -> TYPE
rdataType (RData x) = resourceDataType x

putRData :: RData -> SPut
putRData (RData x) = putResourceData x

---------------------------------------------------------------

-- | IPv4 Address (RFC1035)
newtype RD_A = RD_A IPv4 deriving Eq

instance ResourceData RD_A where
    resourceDataType _ = A
    putResourceData (RD_A ipv4) = mconcat $ map putInt8 (fromIPv4 ipv4)
    getResourceData _ _ = RD_A . toIPv4 <$> getNBytes 4

instance Show RD_A where
    show (RD_A ipv4) = show ipv4

rd_a :: IPv4 -> RData
rd_a ipv4 = toRData $ RD_A ipv4

----------------------------------------------------------------

-- | An authoritative name serve (RFC1035)
newtype RD_NS = RD_NS Domain deriving (Eq)

instance ResourceData RD_NS where
    resourceDataType _ = NS
    putResourceData (RD_NS d) = putDomain d
    getResourceData _ _ = RD_NS <$> getDomain

instance Show RD_NS where
    show (RD_NS d) = show d

rd_ns :: Domain -> RData
rd_ns d = toRData $ RD_NS d

----------------------------------------------------------------

-- | The canonical name for an alias (RFC1035)
newtype RD_CNAME = RD_CNAME Domain deriving (Eq)

instance ResourceData RD_CNAME where
    resourceDataType _ = CNAME
    putResourceData (RD_CNAME d) = putDomain d
    getResourceData _ _ = RD_CNAME <$> getDomain

instance Show RD_CNAME where
    show (RD_CNAME d) = show d

rd_cname :: Domain -> RData
rd_cname d = toRData $ RD_CNAME d

----------------------------------------------------------------

-- | Marks the start of a zone of authority (RFC1035)
data RD_SOA = RD_SOA {
    soaMname   :: Domain
  , soaRname   :: Mailbox
  , soaSerial  :: Word32
  , soaRefresh :: Word32
  , soaRetry   :: Word32
  , soaExpire  :: Word32
  , soaMinimum :: Word32
  } deriving (Eq)

instance ResourceData RD_SOA where
    resourceDataType _ = SOA
    putResourceData RD_SOA{..} =
      mconcat [ putDomain soaMname
              , putMailbox soaRname
              , put32 soaSerial
              , put32 soaRefresh
              , put32 soaRetry
              , put32 soaExpire
              , put32 soaMinimum
              ]
    getResourceData _ _ = RD_SOA <$> getDomain
                                    <*> getMailbox
                                    <*> get32
                                    <*> get32
                                    <*> get32
                                    <*> get32
                                    <*> get32

instance Show RD_SOA where
    show RD_SOA{..} = show soaMname   ++ " "
                   ++ show soaRname   ++ " "
                   ++ show soaSerial  ++ " "
                   ++ show soaRefresh ++ " "
                   ++ show soaRetry   ++ " "
                   ++ show soaExpire  ++ " "
                   ++ show soaMinimum

rd_soa :: Domain -> Mailbox -> Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> RData
rd_soa a b c d e f g = toRData $ RD_SOA a b c d e f g

----------------------------------------------------------------

-- | NULL RR (EXPERIMENTAL, RFC1035).
newtype RD_NULL = RD_NULL Opaque deriving (Eq)

instance ResourceData RD_NULL where
    resourceDataType _ = NULL
    putResourceData (RD_NULL o) = putOpaque o
    getResourceData _ len = RD_NULL <$> getOpaque len

instance Show RD_NULL where
    show (RD_NULL o) = show o

rd_null :: Opaque -> RData
rd_null = toRData . RD_NULL

----------------------------------------------------------------

-- | A domain name pointer (RFC1035)
newtype RD_PTR = RD_PTR Domain deriving (Eq)

instance ResourceData RD_PTR where
    resourceDataType _ = PTR
    putResourceData (RD_PTR d) = putDomain d
    getResourceData _ _ = RD_PTR <$> getDomain

instance Show RD_PTR where
    show (RD_PTR d) = show d

rd_ptr :: Domain -> RData
rd_ptr d = toRData $ RD_PTR d

----------------------------------------------------------------

-- | Mail exchange (RFC1035)
data RD_MX = RD_MX {
    mxPreference :: Word16
  , mxExchange   :: Domain
  } deriving (Eq)

instance ResourceData RD_MX where
    resourceDataType _ = MX
    putResourceData RD_MX{..} =
      mconcat [ put16 mxPreference
              , putDomain mxExchange
              ]
    getResourceData _ _ = RD_MX <$> get16 <*> getDomain

instance Show RD_MX where
    show RD_MX{..} = show mxPreference ++ " " ++ show mxExchange

rd_mx :: Word16 -> Domain -> RData
rd_mx a b = toRData $ RD_MX a b

----------------------------------------------------------------

-- | Text strings (RFC1035)
newtype RD_TXT = RD_TXT Text deriving (Eq)

instance ResourceData RD_TXT where
    resourceDataType _ = TXT
    putResourceData (RD_TXT txt0) = putTXT txt0
      where
        putTXT txt = let (h, t) = T.splitAt 255 txt
                     in putLenText h <> if T.null t
                                               then mempty
                                               else putTXT t
    getResourceData _ len =
      RD_TXT . T.concat <$> sGetMany "TXT RR string" len getstring
        where
          getstring = getInt8 >>= getNText

instance Show RD_TXT where
    show (RD_TXT txt) = '"' : T.foldr dnsesc ['"'] txt
      where
        dnsesc c s
          | c == '"'             = '\\' : c : s
          | c == '\\'            = '\\' : c : s
          | ' ' <= c && c <= '~' =        c : s
          | otherwise            = '\\' : ddd c s
        ddd c s =
            let (q100, r100) = divMod (ord c) 100
                (q10, r10) = divMod r100 10
             in intToDigit q100 : intToDigit q10 : intToDigit r10 : s

rd_txt :: Text -> RData
rd_txt x = toRData $ RD_TXT x

----------------------------------------------------------------

-- | Responsible Person (RFC1183)
data RD_RP = RD_RP Mailbox Domain deriving (Eq)

instance ResourceData RD_RP where
    resourceDataType _ = RP
    putResourceData (RD_RP mbox d) = putMailbox mbox <> putDomain d
    getResourceData _ _ = RD_RP <$> getMailbox <*> getDomain

instance Show RD_RP where
    show (RD_RP mbox d) =
        show mbox ++ " " ++ show d

rd_rp :: Mailbox -> Domain -> RData
rd_rp a b = toRData $ RD_RP a b

----------------------------------------------------------------

-- | IPv6 Address (RFC3596)
newtype RD_AAAA = RD_AAAA IPv6 deriving (Eq)

instance ResourceData RD_AAAA where
    resourceDataType _ = AAAA
    putResourceData (RD_AAAA ipv6) = mconcat $ map putInt8 (fromIPv6b ipv6)
    getResourceData _ _ = RD_AAAA . toIPv6b <$> getNBytes 16

instance Show RD_AAAA where
    show (RD_AAAA ipv6) = show ipv6

rd_aaaa :: IPv6 -> RData
rd_aaaa ipv6 = toRData $ RD_AAAA ipv6

----------------------------------------------------------------

-- | Server Selection (RFC2782)
data RD_SRV = RD_SRV {
    srvPriority :: Word16
  , srvWeight   :: Word16
  , srvPort     :: Word16
  , srvTarget   :: Domain
  } deriving (Eq)

instance ResourceData RD_SRV where
    resourceDataType _ = SRV
    putResourceData RD_SRV{..} =
      mconcat [ put16 srvPriority
              , put16 srvWeight
              , put16 srvPort
              , putDomain srvTarget
              ]
    getResourceData _ _ = RD_SRV <$> get16
                                    <*> get16
                                    <*> get16
                                    <*> getDomain

instance Show RD_SRV where
    show RD_SRV{..} = show srvPriority ++ " "
                   ++ show srvWeight   ++ " "
                   ++ show srvPort     ++ " "
                   ++ show srvTarget

rd_srv :: Word16 -> Word16 -> Word16 -> Domain -> RData
rd_srv a b c d = toRData $ RD_SRV a b c d

----------------------------------------------------------------

-- | DNAME (RFC6672)
newtype RD_DNAME = RD_DNAME Domain deriving (Eq)

instance ResourceData RD_DNAME where
    resourceDataType _ = DNAME
    putResourceData (RD_DNAME d) = putDomain d
    getResourceData _ _ = RD_DNAME <$> getDomain

instance Show RD_DNAME where
    show (RD_DNAME d) = show d

rd_dname :: Domain -> RData
rd_dname d = toRData $ RD_DNAME d

----------------------------------------------------------------

-- | OPT (RFC6891)
newtype RD_OPT = RD_OPT [OData] deriving (Eq)

instance ResourceData RD_OPT where
    resourceDataType _ = OPT
    putResourceData (RD_OPT options) = mconcat $ fmap encodeOData options
    getResourceData = undefined -- never used

instance Show RD_OPT where
    show (RD_OPT options) = show options

rd_opt :: [OData] -> RData
rd_opt x = toRData $ RD_OPT x

----------------------------------------------------------------

-- | TLSA (RFC6698)
data RD_TLSA = RD_TLSA {
    tlsaUsage        :: Word8
  , tlsaSelector     :: Word8
  , tlsaMatchingType :: Word8
  , tlsaAssocData    :: Opaque
  } deriving (Eq)

instance ResourceData RD_TLSA where
    resourceDataType _ = TLSA
    putResourceData RD_TLSA{..} =
      mconcat [ put8 tlsaUsage
              , put8 tlsaSelector
              , put8 tlsaMatchingType
              , putOpaque tlsaAssocData
              ]
    getResourceData _ len =
      RD_TLSA <$> get8
              <*> get8
              <*> get8
              <*> getOpaque (len - 3)

-- Opaque RData: <https://tools.ietf.org/html/rfc3597#section-5>
instance Show RD_TLSA where
    show RD_TLSA{..} = show tlsaUsage        ++ " "
                    ++ show tlsaSelector     ++ " "
                    ++ show tlsaMatchingType ++ " "
                    ++ b16encode (opaqueToByteString tlsaAssocData)

rd_tlsa :: Word8 -> Word8 -> Word8 -> Opaque -> RData
rd_tlsa a b c d = toRData $ RD_TLSA a b c d

----------------------------------------------------------------

-- | Unknown resource data
data RD_Unknown = RD_Unknown TYPE Opaque deriving (Eq, Show)

instance ResourceData RD_Unknown where
    resourceDataType (RD_Unknown typ _) = typ
    putResourceData (RD_Unknown _ o) = putOpaque o
    getResourceData = undefined -- never used

rd_unknown :: TYPE -> Opaque -> RData
rd_unknown a b = toRData $ RD_Unknown a b
