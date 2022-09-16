{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Types.RData where

import qualified Control.Exception as E
import Control.Monad.State (gets)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import Data.Char (intToDigit)
import Data.IP (IPv4, IPv6, fromIPv4, toIPv4, fromIPv6b, toIPv6b)

import DNS.Types.Imports
import DNS.Types.StateBinary
import DNS.Types.Base
import DNS.Types.EDNS

---------------------------------------------------------------

class (Typeable a, Eq a, Show a) => ResourceData a where
    resourceDataType   :: a -> TYPE
    encodeResourceData :: a -> SPut
    decodeResourceData :: proxy a -> Int -> SGet a
    copyResourceData   :: a -> a

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

---------------------------------------------------------------

-- | IPv4 Address (RFC1035)
newtype RD_A = RD_A IPv4 deriving Eq

instance ResourceData RD_A where
    resourceDataType _ = A
    encodeResourceData (RD_A ipv4) = mconcat $ map putInt8 (fromIPv4 ipv4)
    decodeResourceData _ _ = RD_A . toIPv4 <$> getNBytes 4
    copyResourceData x = x

instance Show RD_A where
    show (RD_A ipv4) = show ipv4

rd_a :: IPv4 -> RData
rd_a ipv4 = toRData $ RD_A ipv4

----------------------------------------------------------------

-- | An authoritative name serve (RFC1035)
newtype RD_NS = RD_NS Domain deriving (Eq)

instance ResourceData RD_NS where
    resourceDataType _ = NS
    encodeResourceData (RD_NS d) = putDomain d
    decodeResourceData _ _ = RD_NS <$> getDomain
    copyResourceData (RD_NS dom) = RD_NS $ B.copy dom

instance Show RD_NS where
    show (RD_NS d) = showDomain d

rd_ns :: Domain -> RData
rd_ns d = toRData $ RD_NS d

----------------------------------------------------------------

-- | The canonical name for an alias (RFC1035)
newtype RD_CNAME = RD_CNAME Domain deriving (Eq)

instance ResourceData RD_CNAME where
    resourceDataType _ = CNAME
    encodeResourceData (RD_CNAME d) = putDomain d
    decodeResourceData _ _ = RD_CNAME <$> getDomain
    copyResourceData (RD_CNAME dom) = RD_CNAME $ B.copy dom

instance Show RD_CNAME where
    show (RD_CNAME d) = showDomain d

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
    encodeResourceData RD_SOA{..} =
      mconcat [ putDomain soaMname
              , putMailbox soaRname
              , put32 soaSerial
              , put32 soaRefresh
              , put32 soaRetry
              , put32 soaExpire
              , put32 soaMinimum
              ]
    decodeResourceData _ _ = RD_SOA <$> getDomain
                                    <*> getMailbox
                                    <*> get32
                                    <*> get32
                                    <*> get32
                                    <*> get32
                                    <*> get32
    copyResourceData r@RD_SOA{..} =
        r { soaMname = B.copy soaMname
          , soaRname = B.copy soaRname
          }

instance Show RD_SOA where
    show RD_SOA{..} = showDomain soaMname ++ " "
                   ++ showDomain soaRname ++ " "
                   ++ show soaSerial      ++ " "
                   ++ show soaRefresh     ++ " "
                   ++ show soaRetry       ++ " "
                   ++ show soaExpire      ++ " "
                   ++ show soaMinimum

rd_soa :: Domain -> Mailbox -> Word32 -> Word32 -> Word32 -> Word32 -> Word32 -> RData
rd_soa a b c d e f g = toRData $ RD_SOA a b c d e f g

----------------------------------------------------------------

-- | NULL RR (EXPERIMENTAL, RFC1035).
newtype RD_NULL = RD_NULL ByteString deriving (Eq)

instance ResourceData RD_NULL where
    resourceDataType _ = NULL
    encodeResourceData (RD_NULL bytes) = putByteString bytes
    decodeResourceData _ len = RD_NULL <$> getNByteString len
    copyResourceData (RD_NULL bytes) = RD_NULL $ B.copy bytes

instance Show RD_NULL where
    show (RD_NULL bytes) = showOpaque bytes

rd_null :: ByteString -> RData
rd_null x = toRData $ RD_NULL x

----------------------------------------------------------------

-- | A domain name pointer (RFC1035)
newtype RD_PTR = RD_PTR Domain deriving (Eq)

instance ResourceData RD_PTR where
    resourceDataType _ = PTR
    encodeResourceData (RD_PTR d) = putDomain d
    decodeResourceData _ _ = RD_PTR <$> getDomain
    copyResourceData (RD_PTR dom) = RD_PTR $ B.copy dom

instance Show RD_PTR where
    show (RD_PTR d) = showDomain d

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
    encodeResourceData RD_MX{..} =
      mconcat [ put16 mxPreference
              , putDomain mxExchange
              ]
    decodeResourceData _ _ = RD_MX <$> get16 <*> getDomain
    copyResourceData (RD_MX prf dom) = RD_MX prf $ B.copy dom

instance Show RD_MX where
    show RD_MX{..} = show mxPreference ++ " " ++ showDomain mxExchange

rd_mx :: Word16 -> Domain -> RData
rd_mx a b = toRData $ RD_MX a b

----------------------------------------------------------------

-- | Text strings (RFC1035)
newtype RD_TXT = RD_TXT ByteString deriving (Eq)

instance ResourceData RD_TXT where
    resourceDataType _ = TXT
    encodeResourceData (RD_TXT txt0) = putTXT txt0
      where
        putTXT txt = let (!h, !t) = BS.splitAt 255 txt
                     in putByteStringWithLength h <> if BS.null t
                                                     then mempty
                                                     else putTXT t
    decodeResourceData _ len =
      RD_TXT . B.concat <$> sGetMany "TXT RR string" len getstring
        where
          getstring = getInt8 >>= getNByteString
    copyResourceData (RD_TXT txt) = RD_TXT $ B.copy txt

instance Show RD_TXT where
    show (RD_TXT bs) = '"' : B.foldr dnsesc ['"'] bs
      where
        c2w = fromIntegral . fromEnum
        w2c = toEnum . fromIntegral
        doubleQuote = c2w '"'
        backSlash   = c2w '\\'
        dnsesc c s
          | c == doubleQuote   = '\\' : w2c c : s
          | c == backSlash     = '\\' : w2c c : s
          | c >= 32 && c < 127 =        w2c c : s
          | otherwise          = '\\' : ddd c   s
        ddd c s =
            let (q100, r100) = divMod (fromIntegral c) 100
                (q10, r10) = divMod r100 10
             in intToDigit q100 : intToDigit q10 : intToDigit r10 : s

rd_txt :: ByteString -> RData
rd_txt x = toRData $ RD_TXT x

----------------------------------------------------------------

-- | Responsible Person (RFC1183)
data RD_RP = RD_RP Mailbox Domain deriving (Eq)

instance ResourceData RD_RP where
    resourceDataType _ = RP
    encodeResourceData (RD_RP mbox d) = putMailbox mbox <> putDomain d
    decodeResourceData _ _ = RD_RP <$> getMailbox <*> getDomain
    copyResourceData (RD_RP mbox dname) = RD_RP (B.copy mbox) (B.copy dname)

instance Show RD_RP where
    show (RD_RP mbox d) =
        showDomain mbox ++ " " ++ showDomain d

rd_rp :: Mailbox -> Domain -> RData
rd_rp a b = toRData $ RD_RP a b

----------------------------------------------------------------

-- | IPv6 Address (RFC3596)
newtype RD_AAAA = RD_AAAA IPv6 deriving (Eq)

instance ResourceData RD_AAAA where
    resourceDataType _ = AAAA
    encodeResourceData (RD_AAAA ipv6) = mconcat $ map putInt8 (fromIPv6b ipv6)
    decodeResourceData _ _ = RD_AAAA . toIPv6b <$> getNBytes 16
    copyResourceData x = x

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
    encodeResourceData RD_SRV{..} =
      mconcat [ put16 srvPriority
              , put16 srvWeight
              , put16 srvPort
              , putDomain srvTarget
              ]
    decodeResourceData _ _ = RD_SRV <$> get16
                                    <*> get16
                                    <*> get16
                                    <*> getDomain
    copyResourceData r@RD_SRV{..} = r { srvTarget = B.copy srvTarget }

instance Show RD_SRV where
    show RD_SRV{..} = show srvPriority ++ " "
                   ++ show srvWeight   ++ " "
                   ++ show srvPort     ++ " "
                   ++ BS.unpack srvTarget

rd_srv :: Word16 -> Word16 -> Word16 -> Domain -> RData
rd_srv a b c d = toRData $ RD_SRV a b c d

----------------------------------------------------------------

-- | DNAME (RFC6672)
newtype RD_DNAME = RD_DNAME Domain deriving (Eq)

instance ResourceData RD_DNAME where
    resourceDataType _ = DNAME
    encodeResourceData (RD_DNAME d) = putDomain d
    decodeResourceData _ _ = RD_DNAME <$> getDomain
    copyResourceData (RD_DNAME dom) = RD_DNAME $ B.copy dom

instance Show RD_DNAME where
    show (RD_DNAME d) = showDomain d

rd_dname :: Domain -> RData
rd_dname d = toRData $ RD_DNAME d

----------------------------------------------------------------

-- | OPT (RFC6891)
newtype RD_OPT = RD_OPT [OData] deriving (Eq)

instance ResourceData RD_OPT where
    resourceDataType _ = OPT
    encodeResourceData (RD_OPT options) = mconcat $ fmap encodeOData options
    decodeResourceData = undefined -- never used
    copyResourceData (RD_OPT od) = RD_OPT $ map copyOData od

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
  , tlsaAssocData    :: ByteString
  } deriving (Eq)

instance ResourceData RD_TLSA where
    resourceDataType _ = TLSA
    encodeResourceData RD_TLSA{..} =
      mconcat [ put8 tlsaUsage
              , put8 tlsaSelector
              , put8 tlsaMatchingType
              , putByteString tlsaAssocData
              ]
    decodeResourceData _ len =
      RD_TLSA <$> get8
              <*> get8
              <*> get8
              <*> getNByteString (len - 3)
    copyResourceData (RD_TLSA a b c dgst) = RD_TLSA a b c $ B.copy dgst

-- Opaque RData: <https://tools.ietf.org/html/rfc3597#section-5>
instance Show RD_TLSA where
    show RD_TLSA{..} = show tlsaUsage        ++ " "
                    ++ show tlsaSelector     ++ " "
                    ++ show tlsaMatchingType ++ " "
                    ++ _b16encode tlsaAssocData

rd_tlsa :: Word8 -> Word8 -> Word8 -> ByteString -> RData
rd_tlsa a b c d = toRData $ RD_TLSA a b c d

----------------------------------------------------------------

-- | Unknown resource data
data RD_Unknown = RD_Unknown TYPE ByteString deriving (Eq, Show)

instance ResourceData RD_Unknown where
    resourceDataType (RD_Unknown typ _) = typ
    encodeResourceData (RD_Unknown _ bytes) = putByteString bytes
    decodeResourceData = undefined -- never used
    copyResourceData (RD_Unknown t x)  = RD_Unknown t $ B.copy x

rd_unknown :: TYPE -> ByteString -> RData
rd_unknown a b = toRData $ RD_Unknown a b

----------------------------------------------------------------

showSalt :: ByteString -> String
showSalt ""    = "-"
showSalt salt  = _b16encode salt

showDomain :: ByteString -> String
showDomain = BS.unpack

showOpaque :: ByteString -> String
showOpaque bs = unwords ["\\#", show (BS.length bs), _b16encode bs]

----------------------------------------------------------------

-- In the case of the TXT record, we need to put the string length
-- fixme : What happens with the length > 256 ?
putByteStringWithLength :: BS.ByteString -> SPut
putByteStringWithLength bs = putInt8 (fromIntegral $ BS.length bs) -- put the length of the given string
                          <> putByteString bs

rootDomain :: Domain
rootDomain = BS.pack "."

putDomain :: Domain -> SPut
putDomain = putDomain' '.'

putMailbox :: Mailbox -> SPut
putMailbox = putDomain' '@'

putDomain' :: Char -> ByteString -> SPut
putDomain' sep dom
    | BS.null dom || dom == rootDomain = put8 0
    | otherwise = do
        mpos <- wsPop dom
        cur <- gets wsPosition
        case mpos of
            Just pos -> putPointer pos
            Nothing  -> do
                        -- Pointers are limited to 14-bits!
                        when (cur <= 0x3fff) $ wsPush dom cur
                        mconcat [ putPartialDomain hd
                                , putDomain' '.' tl
                                ]
  where
    -- Try with the preferred separator if present, else fall back to '.'.
    (hd, tl) = loop (c2w sep)
      where
        loop w = case parseLabel w dom of
            Right p | w /= 0x2e && BS.null (snd p) -> loop 0x2e
                    | otherwise -> p
            Left e -> E.throw e

    c2w = fromIntegral . fromEnum

putPointer :: Int -> SPut
putPointer pos = putInt16 (pos .|. 0xc000)

putPartialDomain :: Domain -> SPut
putPartialDomain = putByteStringWithLength

----------------------------------------------------------------

-- | Pointers MUST point back into the packet per RFC1035 Section 4.1.4.  This
-- is further interpreted by the DNS community (from a discussion on the IETF
-- DNSOP mailing list) to mean that they don't point back into the same domain.
-- Therefore, when starting to parse a domain, the current offset is also a
-- strict upper bound on the targets of any pointers that arise while processing
-- the domain.  When following a pointer, the target again becomes a stict upper
-- bound for any subsequent pointers.  This results in a simple loop-prevention
-- algorithm, each sequence of valid pointer values is necessarily strictly
-- decreasing!  The third argument to 'getDomain'' is a strict pointer upper
-- bound, and is set here to the position at the start of parsing the domain
-- or mailbox.
--
-- Note: the separator passed to 'getDomain'' is required to be either \'.\' or
-- \'\@\', or else 'unparseLabel' needs to be modified to handle the new value.
--

getDomain :: SGet Domain
getDomain = getPosition >>= getDomain' dot

getMailbox :: SGet Mailbox
getMailbox = getPosition >>= getDomain' atsign

dot, atsign :: Word8
dot    = fromIntegral $ fromEnum '.' -- 46
atsign = fromIntegral $ fromEnum '@' -- 64

-- $
-- Pathological case: pointer embedded inside a label!  The pointer points
-- behind the start of the domain and is then absorbed into the initial label!
-- Though we don't IMHO have to support this, it is not manifestly illegal, and
-- does exercise the code in an interesting way.  Ugly as this is, it also
-- "works" the same in Perl's Net::DNS and reportedly in ISC's BIND.
--
-- >>> :{
-- let input = "\6\3foo\192\0\3bar\0"
--     parser = skipNBytes 1 >> getDomain' dot 1
--     Right (output, _) = runSGet parser input
--  in output == "foo.\\003foo\\192\\000.bar."
-- :}
-- True
--
-- The case below fails to point far enough back, and triggers the loop
-- prevention code-path.
--
-- >>> :{
-- let input = "\6\3foo\192\1\3bar\0"
--     parser = skipNBytes 1 >> getDomain' dot 1
--     Left (DecodeError err) = runSGet parser input
--  in err
-- :}
-- "invalid name compression pointer"

-- | Get a domain name, using sep1 as the separator between the 1st and 2nd
-- label.  Subsequent labels (and always the trailing label) are terminated
-- with a ".".
--
-- Note: the separator is required to be either \'.\' or \'\@\', or else
-- 'unparseLabel' needs to be modified to handle the new value.
--
-- Domain name compression pointers must always refer to a position that
-- precedes the start of the current domain name.  The starting offsets form a
-- strictly decreasing sequence, which prevents pointer loops.
--
getDomain' :: Word8 -> Int -> SGet ByteString
getDomain' sep1 ptrLimit = do
    pos <- getPosition
    c <- getInt8
    let n = getValue c
    getdomain pos c n
  where
    -- Reprocess the same ByteString starting at the pointer
    -- target (offset).
    getPtr pos offset = do
        msg <- getInput
        let parser = skipNBytes offset >> getDomain' sep1 offset
        case runSGet parser msg of
            Left (DecodeError err) -> failSGet err
            Left err               -> fail $ show err
            Right o                -> do
                -- Cache only the presentation form decoding of domain names,
                -- mailboxes (e.g. SOA rname) are less frequently reused, and
                -- have a different presentation form, so must not share the
                -- same cache.
                when (sep1 == dot) $
                    push pos (fst o)
                return (fst o)

    getdomain pos c n
      | c == 0 = return "." -- Perhaps the root domain?
      | isPointer c = do
          d <- getInt8
          let offset = n * 256 + d
          when (offset >= ptrLimit) $
              failSGet "invalid name compression pointer"
          if sep1 /= dot
              then getPtr pos offset
              else pop offset >>= \case
                  Nothing -> getPtr pos offset
                  Just o  -> return o
      -- As for now, extended labels have no use.
      -- This may change some time in the future.
      | isExtLabel c = return ""
      | otherwise = do
          hs <- unparseLabel sep1 <$> getNByteString n
          ds <- getDomain' dot ptrLimit
          let dom = case ds of -- avoid trailing ".."
                  "." -> hs <> "."
                  _   -> hs <> B.singleton sep1 <> ds
          push pos dom
          return dom
    getValue c = c .&. 0x3f
    isPointer c = testBit c 7 && testBit c 6
    isExtLabel c = not (testBit c 7) && testBit c 6
