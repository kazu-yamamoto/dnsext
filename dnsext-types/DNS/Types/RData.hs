{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Types.RData where

import Data.Char (chr)
import Data.IP (IPv4, IPv6, fromIPv4, toIPv4, fromIPv6b, toIPv6b)
import Data.Word8

import DNS.StateBinary
import DNS.Types.Domain
import DNS.Types.EDNS
import DNS.Types.Imports
import DNS.Types.Opaque.Internal (Opaque, putOpaque, putLenOpaque, getOpaque, getLenOpaque)
import qualified DNS.Types.Opaque.Internal as Opaque
import DNS.Types.Seconds
import DNS.Types.Type

---------------------------------------------------------------

class (Typeable a, Eq a, Show a) => ResourceData a where
    resourceDataType :: a -> TYPE
    putResourceData  :: CanonicalFlag -> a -> SPut
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

putRData :: CanonicalFlag -> RData -> SPut
putRData cf (RData x) = putResourceData cf x

rdataField :: forall a b . Typeable a => RData -> (a -> b) -> Maybe b
rdataField rd f = case fromRData rd of
  Nothing       -> Nothing
  Just (x :: a) -> Just $ f x

---------------------------------------------------------------

-- | IPv4 Address (RFC1035)
newtype RD_A = RD_A {
    -- | Setter/getter for 'IPv4'.
    a_ipv4 :: IPv4
  } deriving (Eq, Ord)

instance ResourceData RD_A where
    resourceDataType _ = A
    putResourceData _ (RD_A ipv4) = mconcat $ map putInt8 (fromIPv4 ipv4)
    getResourceData _ _ = RD_A . toIPv4 <$> getNBytes 4

instance Show RD_A where
    show (RD_A ipv4) = show ipv4

-- | Smart constructor.
rd_a :: IPv4 -> RData
rd_a ipv4 = toRData $ RD_A ipv4

----------------------------------------------------------------

-- | An authoritative name serve (RFC1035)
newtype RD_NS = RD_NS {
    -- | Setter/getter for 'Domain'.
    ns_domain :: Domain
  } deriving (Eq, Ord)

instance ResourceData RD_NS where
    resourceDataType _ = NS
    putResourceData cf (RD_NS d) = putDomain cf d
    getResourceData _ _ = RD_NS <$> getDomain

instance Show RD_NS where
    show (RD_NS d) = show d

-- | Smart constructor.
rd_ns :: Domain -> RData
rd_ns d = toRData $ RD_NS d

----------------------------------------------------------------

-- | The canonical name for an alias (RFC1035)
newtype RD_CNAME = RD_CNAME {
    -- | Setter/getter for 'Domain'.
    cname_domain :: Domain
  } deriving  (Eq, Ord)

instance ResourceData RD_CNAME where
    resourceDataType _ = CNAME
    putResourceData cf (RD_CNAME d) = putDomain cf d
    getResourceData _ _ = RD_CNAME <$> getDomain

instance Show RD_CNAME where
    show (RD_CNAME d) = show d

-- | Smart constructor.
rd_cname :: Domain -> RData
rd_cname d = toRData $ RD_CNAME d

----------------------------------------------------------------

-- | Marks the start of a zone of authority (RFC1035)
data RD_SOA = RD_SOA {
    -- | Setter/getter for mname
    soa_mname   :: Domain
    -- | Setter/getter for rname
  , soa_rname   :: Mailbox
    -- | Setter/getter for serial
  , soa_serial  :: Word32
    -- | Setter/getter for refresh
  , soa_refresh :: Seconds
    -- | Setter/getter for retry
  , soa_retry   :: Seconds
    -- | Setter/getter for expire
  , soa_expire  :: Seconds
    -- | Setter/getter for minimum
  , soa_minimum :: Seconds
  } deriving (Eq, Ord, Show)

instance ResourceData RD_SOA where
    resourceDataType _ = SOA
    putResourceData cf RD_SOA{..} =
      mconcat [ putDomain  cf soa_mname
              , putMailbox cf soa_rname
              , put32      soa_serial
              , putSeconds soa_refresh
              , putSeconds soa_retry
              , putSeconds soa_expire
              , putSeconds soa_minimum
              ]
    getResourceData _ _ = RD_SOA <$> getDomain
                                    <*> getMailbox
                                    <*> get32
                                    <*> getSeconds
                                    <*> getSeconds
                                    <*> getSeconds
                                    <*> getSeconds

-- | Smart constructor.
rd_soa :: Domain -> Mailbox -> Word32 -> Seconds -> Seconds -> Seconds -> Seconds -> RData
rd_soa a b c d e f g = toRData $ RD_SOA a b c d e f g

----------------------------------------------------------------

-- | NULL RR (EXPERIMENTAL, RFC1035).
newtype RD_NULL = RD_NULL {
    -- | Setter/getter for 'Opaque'.
    null_opaque :: Opaque
  } deriving (Eq, Ord)

instance ResourceData RD_NULL where
    resourceDataType _ = NULL
    putResourceData _ (RD_NULL o) = putOpaque o
    getResourceData _ len = RD_NULL <$> getOpaque len

instance Show RD_NULL where
    show (RD_NULL o) = show o

rd_null :: Opaque -> RData
rd_null = toRData . RD_NULL

----------------------------------------------------------------

-- | A domain name pointer (RFC1035)
newtype RD_PTR = RD_PTR {
    -- | Setter/getter for 'Domain'
    ptr_domain :: Domain
  } deriving (Eq, Ord)

instance ResourceData RD_PTR where
    resourceDataType _ = PTR
    putResourceData cf (RD_PTR d) = putDomain cf d
    getResourceData _ _ = RD_PTR <$> getDomain

instance Show RD_PTR where
    show (RD_PTR d) = show d

-- | Smart constructor.
rd_ptr :: Domain -> RData
rd_ptr d = toRData $ RD_PTR d

----------------------------------------------------------------

-- | Mail exchange (RFC1035)
data RD_MX = RD_MX {
    -- | Setter/getter for preference
    mx_preference :: Word16
    -- | Setter/getter for 'Domain'
  , mx_exchange   :: Domain
  } deriving (Eq, Ord, Show)

instance ResourceData RD_MX where
    resourceDataType _ = MX
    putResourceData cf RD_MX{..} =
      mconcat [ put16 mx_preference
              , putDomain cf mx_exchange
              ]
    getResourceData _ _ = RD_MX <$> get16 <*> getDomain

-- | Smart constructor.
rd_mx :: Word16 -> Domain -> RData
rd_mx a b = toRData $ RD_MX a b

----------------------------------------------------------------

-- | Text strings (RFC1035)
newtype RD_TXT = RD_TXT {
    -- | Setter/getter for 'Opaque'
    txt_opaque :: Opaque
  } deriving (Eq, Ord)

instance ResourceData RD_TXT where
    resourceDataType _ = TXT
    putResourceData _ (RD_TXT o) = putTXT o
      where
        putTXT txt = let (h, t) = Opaque.splitAt 255 txt
                         next | Opaque.null t = mempty
                              | otherwise     = putTXT t
                     in putLenOpaque h <> next
    getResourceData _ len =
      RD_TXT . Opaque.concat <$> sGetMany "TXT RR string" len getLenOpaque

instance Show RD_TXT where
    show (RD_TXT o) = '"' : conv o '"'
      where
        conv t c = Opaque.foldr escape [c] t
        escape :: Word8 -> [Char] -> [Char]
        escape w s
          | w == _quotedbl             = '\\' : c : s
          | w == _backslash            = '\\' : c : s
          | _space <= w && w <= _tilde =        c : s
          | otherwise                  = '\\' : ddd w s
          where
            c = w8ToChar w
        ddd w s =
            let (q100, r100) = divMod w 100
                (q10,  r10)  = divMod r100 10
             in w8ToDigit q100 : w8ToDigit q10 : w8ToDigit r10 : s
        w8ToDigit w = chr $ fromIntegral (w + _0)
        w8ToChar    = chr . fromIntegral

-- | Smart constructor.
rd_txt :: Opaque -> RData
rd_txt x = toRData $ RD_TXT x

----------------------------------------------------------------

-- | Responsible Person (RFC1183)
data RD_RP = RD_RP {
    rp_mbox :: Mailbox
  , rp_domain :: Domain
  }deriving (Eq, Ord, Show)

instance ResourceData RD_RP where
    resourceDataType _ = RP
    putResourceData cf (RD_RP mbox d) = putMailbox cf mbox <> putDomain cf d
    getResourceData _ _ = RD_RP <$> getMailbox <*> getDomain

-- | Smart constructor.
rd_rp :: Mailbox -> Domain -> RData
rd_rp a b = toRData $ RD_RP a b

----------------------------------------------------------------

-- | IPv6 Address (RFC3596)
newtype RD_AAAA = RD_AAAA {
    -- | Setter/getter for 'IPv6'
    aaaa_ipv6 :: IPv6
  } deriving (Eq, Ord)

instance ResourceData RD_AAAA where
    resourceDataType _ = AAAA
    putResourceData _ (RD_AAAA ipv6) = mconcat $ map putInt8 (fromIPv6b ipv6)
    getResourceData _ _ = RD_AAAA . toIPv6b <$> getNBytes 16

instance Show RD_AAAA where
    show (RD_AAAA ipv6) = show ipv6

-- | Smart constructor.
rd_aaaa :: IPv6 -> RData
rd_aaaa ipv6 = toRData $ RD_AAAA ipv6

----------------------------------------------------------------

-- | Server Selection (RFC2782)
data RD_SRV = RD_SRV {
    srv_priority :: Word16
  , srv_weight   :: Word16
  , srv_port     :: Word16
  , srv_target   :: Domain
  } deriving (Eq, Ord, Show)

instance ResourceData RD_SRV where
    resourceDataType _ = SRV
    putResourceData cf RD_SRV{..} =
      mconcat [ put16 srv_priority
              , put16 srv_weight
              , put16 srv_port
              , putDomain cf srv_target
              ]
    getResourceData _ _ = RD_SRV <$> get16
                                    <*> get16
                                    <*> get16
                                    <*> getDomain

-- | Smart constructor.
rd_srv :: Word16 -> Word16 -> Word16 -> Domain -> RData
rd_srv a b c d = toRData $ RD_SRV a b c d

----------------------------------------------------------------

-- | DNAME (RFC6672)
newtype RD_DNAME = RD_DNAME {
    dname_target :: Domain
  } deriving (Eq, Ord)

instance ResourceData RD_DNAME where
    resourceDataType _ = DNAME
    putResourceData cf (RD_DNAME d) = putDomain cf d
    getResourceData _ _ = RD_DNAME <$> getDomain

instance Show RD_DNAME where
    show (RD_DNAME d) = show d

-- | Smart constructor.
rd_dname :: Domain -> RData
rd_dname d = toRData $ RD_DNAME d

----------------------------------------------------------------

-- | OPT (RFC6891)
newtype RD_OPT = RD_OPT {
    opt_odata :: [OData]
  } deriving Eq

instance ResourceData RD_OPT where
    resourceDataType _ = OPT
    putResourceData _ (RD_OPT options) = mconcat $ fmap encodeOData options
    getResourceData = undefined -- never used

instance Show RD_OPT where
    show (RD_OPT options) = show options

-- | Smart constructor.
rd_opt :: [OData] -> RData
rd_opt x = toRData $ RD_OPT x

----------------------------------------------------------------

-- | TLSA (RFC6698)
data RD_TLSA = RD_TLSA {
    tlsa_usage         :: Word8
  , tlsa_selector      :: Word8
  , tlsa_matching_type :: Word8
  , tlsa_assoc_data    :: Opaque
  } deriving (Eq, Ord, Show)

instance ResourceData RD_TLSA where
    resourceDataType _ = TLSA
    putResourceData _ RD_TLSA{..} =
      mconcat [ put8 tlsa_usage
              , put8 tlsa_selector
              , put8 tlsa_matching_type
              , putOpaque tlsa_assoc_data
              ]
    getResourceData _ len =
      RD_TLSA <$> get8
              <*> get8
              <*> get8
              <*> getOpaque (len - 3)

-- | Smart constructor.
rd_tlsa :: Word8 -> Word8 -> Word8 -> Opaque -> RData
rd_tlsa a b c d = toRData $ RD_TLSA a b c d

----------------------------------------------------------------

-- | Unknown resource data
data RD_Unknown = RD_Unknown TYPE Opaque deriving (Eq, Ord, Show)

instance ResourceData RD_Unknown where
    resourceDataType (RD_Unknown typ _) = typ
    putResourceData _ (RD_Unknown _ o) = putOpaque o
    getResourceData = undefined -- never used

-- | Smart constructor.
rd_unknown :: TYPE -> Opaque -> RData
rd_unknown a b = toRData $ RD_Unknown a b
