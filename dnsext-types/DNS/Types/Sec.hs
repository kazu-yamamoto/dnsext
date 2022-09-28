{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TransformListComp #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Types.Sec (
    RD_RRSIG(..)
  , RD_DS(..)
  , RD_NSEC(..)
  , RD_DNSKEY(..)
  , RD_NSEC3(..)
  , RD_NSEC3PARAM(..)
  , RD_CDS(..)
  , RD_CDNSKEY(..)
  , getTYPE
  , dnsTime
  , rd_rrsig
  , rd_ds
  , rd_nsec
  , rd_dnskey
  , rd_nsec3
  , rd_nsec3param
  , rd_cds
  , rd_cdnskey
  ) where

import qualified Data.Hourglass as H
import GHC.Exts (the, groupWith)

import DNS.StateBinary
import DNS.Types.Domain
import DNS.Types.Imports
import DNS.Types.Opaque
import DNS.Types.RData
import DNS.Types.Type

----------------------------------------------------------------

-- | DNSSEC signature
--
-- As noted in
-- <https://tools.ietf.org/html/rfc4034#section-3.1.5 Section 3.1.5 of RFC 4034>
-- the RRsig inception and expiration times use serial number arithmetic.  As a
-- result these timestamps /are not/ pure values, their meaning is
-- time-dependent!  They depend on the present time and are both at most
-- approximately +\/-68 years from the present.  This ambiguity is not a
-- problem because cached RRSIG records should only persist a few days,
-- signature lifetimes should be *much* shorter than 68 years, and key rotation
-- should result any misconstrued 136-year-old signatures fail to validate.
-- This also means that the interpretation of a time that is exactly half-way
-- around the clock at @now +\/-0x80000000@ is not important, the signature
-- should never be valid.
--
-- The upshot for us is that we need to convert these *impure* relative values
-- to pure absolute values at the moment they are received from from the network
-- (or read from files, ... in some impure I/O context), and convert them back to
-- 32-bit values when encoding.  Therefore, the constructor takes absolute
-- 64-bit representations of the inception and expiration times.
--
-- The 'dnsTime' function performs the requisite conversion.
--
data RD_RRSIG = RD_RRSIG {
    rrsigType       :: TYPE   -- ^ RRtype of RRset signed
  , rrsigKeyAlg     :: Word8  -- ^ DNSKEY algorithm
  , rrsigNumLabels  :: Word8  -- ^ Number of labels signed
  , rrsigTTL        :: Word32 -- ^ Maximum origin TTL
  , rrsigExpiration :: Int64  -- ^ Time last valid
  , rrsigInception  :: Int64  -- ^ Time first valid
  , rrsigKeyTag     :: Word16 -- ^ Signing key tag
  , rrsigZone       :: Domain -- ^ Signing domain
  , rrsigValue      :: Opaque -- ^ Opaque signature
  } deriving (Eq, Ord)

instance ResourceData RD_RRSIG where
    resourceDataType _ = RRSIG
    putResourceData RD_RRSIG{..} =
      mconcat [ put16 $ fromTYPE rrsigType
              , put8    rrsigKeyAlg
              , put8    rrsigNumLabels
              , put32   rrsigTTL
              , put32 $ fromIntegral rrsigExpiration
              , put32 $ fromIntegral rrsigInception
              , put16   rrsigKeyTag
              , putDomain rrsigZone
              , putOpaque rrsigValue
              ]
    getResourceData _ lim = do
        -- The signature follows a variable length zone name
        -- and occupies the rest of the RData.  Simplest to
        -- checkpoint the position at the start of the RData,
        -- and after reading the zone name, and subtract that
        -- from the RData length.
        --
        end <- rdataEnd lim
        typ <- getTYPE
        alg <- get8
        cnt <- get8
        ttl <- get32
        tex <- getDnsTime
        tin <- getDnsTime
        tag <- get16
        dom <- getDomain -- XXX: Enforce no compression?
        pos <- parserPosition
        val <- getOpaque $ end - pos
        return $ RD_RRSIG typ alg cnt ttl tex tin tag dom val
      where
        getDnsTime   = do
            tnow <- getAtTime
            tdns <- get32
            return $ dnsTime tdns tnow

instance Show RD_RRSIG where
    show RD_RRSIG{..} =
        unwords [ show rrsigType
                , show rrsigKeyAlg
                , show rrsigNumLabels
                , show rrsigTTL
                , showTime rrsigExpiration
                , showTime rrsigInception
                , show rrsigKeyTag
                , show rrsigZone
                , b64encode (opaqueToByteString rrsigValue)
                ]
      where
        showTime :: Int64 -> String
        showTime t = H.timePrint fmt $ H.Elapsed $ H.Seconds t
          where
            fmt = [ H.Format_Year4, H.Format_Month2, H.Format_Day2
                  , H.Format_Hour,  H.Format_Minute, H.Format_Second ]

rd_rrsig :: TYPE -> Word8 -> Word8 -> Word32 -> Int64 -> Int64 -> Word16 -> Domain -> Opaque -> RData
rd_rrsig a b c d e f g h i = toRData $ RD_RRSIG a b c d e f g h i

----------------------------------------------------------------

-- | Delegation Signer (RFC4034)
data RD_DS = RD_DS {
    dsKeyTag     :: Word16
  , dsAlgorithm  :: Word8
  , dsDigestType :: Word8
  , dsDigest     :: Opaque
  } deriving (Eq)

instance ResourceData RD_DS where
    resourceDataType _ = DS
    putResourceData RD_DS{..} =
        mconcat [ put16 dsKeyTag
                , put8 dsAlgorithm
                , put8 dsDigestType
                , putOpaque dsDigest
                ]
    getResourceData _ lim =
        RD_DS <$> get16
              <*> get8
              <*> get8
              <*> getOpaque (lim - 4)

instance Show RD_DS where
    show RD_DS{..} = show dsKeyTag     ++ " "
                  ++ show dsAlgorithm  ++ " "
                  ++ show dsDigestType ++ " "
                  ++ b16encode (opaqueToByteString dsDigest)

rd_ds :: Word16 -> Word8 -> Word8 -> Opaque -> RData
rd_ds a b c d = toRData $ RD_DS a b c d

----------------------------------------------------------------

-- | DNSSEC denial of existence NSEC record
data RD_NSEC = RD_NSEC {
    nsecNextDomain :: Domain
  , nsecTypes      :: [TYPE]
  } deriving (Eq)

instance ResourceData RD_NSEC where
    resourceDataType _ = NSEC
    putResourceData RD_NSEC{..} =
        putDomain nsecNextDomain <> putNsecTypes nsecTypes
    getResourceData _ len = do
        end <- rdataEnd len
        dom <- getDomain
        pos <- parserPosition
        RD_NSEC dom <$> getNsecTypes (end - pos)

instance Show RD_NSEC where
    show RD_NSEC{..} =
        unwords $ show nsecNextDomain : map show nsecTypes

rd_nsec :: Domain -> [TYPE] -> RData
rd_nsec a b = toRData $ RD_NSEC a b

----------------------------------------------------------------

-- | DNSKEY (RFC4034)
data RD_DNSKEY = RD_DNSKEY {
    dnskeyFlags     :: Word16
  , dnskeyProtocol  :: Word8
  , dnskeyAlgorithm :: Word8
  , dnskeyPublicKey :: Opaque
  } deriving (Eq)

instance ResourceData RD_DNSKEY where
    resourceDataType _ = DNSKEY
    putResourceData RD_DNSKEY{..} =
        mconcat [ put16 dnskeyFlags
                , put8  dnskeyProtocol
                , put8  dnskeyAlgorithm
                , putShortByteString (opaqueToShortByteString dnskeyPublicKey)
                ]
    getResourceData _ len =
        RD_DNSKEY <$> get16
                  <*> get8
                  <*> get8
                  <*> getOpaque (len - 4)

-- <https://tools.ietf.org/html/rfc5155#section-3.2>
instance Show RD_DNSKEY where
    show RD_DNSKEY{..} = show dnskeyFlags     ++ " "
                      ++ show dnskeyProtocol  ++ " "
                      ++ show dnskeyAlgorithm ++ " "
                      ++ b64encode (opaqueToByteString dnskeyPublicKey)

rd_dnskey :: Word16 -> Word8 -> Word8 -> Opaque -> RData
rd_dnskey a b c d = toRData $ RD_DNSKEY a b c d

----------------------------------------------------------------

-- | DNSSEC hashed denial of existence (RFC5155)
data RD_NSEC3 = RD_NSEC3 {
    nsec3HashAlgorithm       :: Word8
  , nsec3Flags               :: Word8
  , nsec3Iterations          :: Word16
  , nsec3Salt                :: Opaque
  , nsec3NextHashedOwnerName :: Opaque
  , nsec3Types               :: [TYPE]
  } deriving (Eq)

instance ResourceData RD_NSEC3 where
    resourceDataType _ = NSEC3
    putResourceData RD_NSEC3{..} =
        mconcat [ put8 nsec3HashAlgorithm
                , put8 nsec3Flags
                , put16 nsec3Iterations
                , putLenOpaque nsec3Salt
                , putLenOpaque nsec3NextHashedOwnerName
                , putNsecTypes nsec3Types
                ]
    getResourceData _ len = do
        dend <- rdataEnd len
        halg <- get8
        flgs <- get8
        iter <- get16
        salt <- getLenOpaque
        hash <- getLenOpaque
        tpos <- parserPosition
        RD_NSEC3 halg flgs iter salt hash <$> getNsecTypes (dend - tpos)

instance Show RD_NSEC3 where
    show RD_NSEC3{..} = unwords $ show nsec3HashAlgorithm
                                : show nsec3Flags
                                : show nsec3Iterations
                                : showSalt nsec3Salt
                                : b32encode (opaqueToByteString nsec3NextHashedOwnerName)
                                : map show nsec3Types

rd_nsec3 :: Word8 -> Word8 -> Word16 -> Opaque -> Opaque -> [TYPE] -> RData
rd_nsec3 a b c d e f = toRData $ RD_NSEC3 a b c d e f

----------------------------------------------------------------

-- | NSEC3 zone parameters (RFC5155)
data RD_NSEC3PARAM = RD_NSEC3PARAM {
    nsec3paramHashAlgorithm :: Word8
  , nsec3paramFlags         :: Word8
  , nsec3paramIterations    :: Word16
  , nsec3paramSalt          :: Opaque
  } deriving (Eq)

instance ResourceData RD_NSEC3PARAM where
    resourceDataType _ = NSEC3PARAM
    putResourceData RD_NSEC3PARAM{..} =
        mconcat [ put8  nsec3paramHashAlgorithm
                , put8  nsec3paramFlags
                , put16 nsec3paramIterations
                , putLenOpaque nsec3paramSalt
                ]
    getResourceData _ _ =
        RD_NSEC3PARAM <$> get8
                      <*> get8
                      <*> get16
                      <*> getLenOpaque

instance Show RD_NSEC3PARAM where
    show RD_NSEC3PARAM{..} = show nsec3paramHashAlgorithm ++ " "
                          ++ show nsec3paramFlags         ++ " "
                          ++ show nsec3paramIterations    ++ " "
                          ++ showSalt nsec3paramSalt

rd_nsec3param :: Word8 -> Word8 -> Word16 -> Opaque -> RData
rd_nsec3param a b c d = toRData $ RD_NSEC3PARAM a b c d

----------------------------------------------------------------

-- | Child DS (RFC7344)
newtype RD_CDS = RD_CDS RD_DS deriving (Eq)

instance ResourceData RD_CDS where
    resourceDataType _ = CDS
    putResourceData (RD_CDS ds) = putResourceData ds
    getResourceData _ len = RD_CDS <$> getResourceData (Proxy :: Proxy RD_DS) len

instance Show RD_CDS where
    show (RD_CDS ds) = show ds

rd_cds :: Word16 -> Word8 -> Word8 -> Opaque -> RData
rd_cds a b c d = toRData $ RD_CDS $ RD_DS a b c d

----------------------------------------------------------------

-- | Child DNSKEY (RFC7344)
newtype RD_CDNSKEY = RD_CDNSKEY RD_DNSKEY deriving (Eq)

instance ResourceData RD_CDNSKEY where
    resourceDataType _ = CDNSKEY
    putResourceData (RD_CDNSKEY dnskey) = putResourceData dnskey
    getResourceData _ len =RD_CDNSKEY <$> getResourceData (Proxy :: Proxy RD_DNSKEY) len

instance Show RD_CDNSKEY where
    show (RD_CDNSKEY dnskey) = show dnskey

rd_cdnskey :: Word16 -> Word8 -> Word8 -> Opaque -> RData
rd_cdnskey a b c d = toRData $ RD_CDNSKEY $ RD_DNSKEY a b c d

----------------------------------------------------------------

-- | Given a 32-bit circle-arithmetic DNS time, and the current absolute epoch
-- time, return the epoch time corresponding to the DNS timestamp.
--
dnsTime :: Word32 -- ^ DNS circle-arithmetic timestamp
        -> Int64  -- ^ current epoch time
        -> Int64  -- ^ absolute DNS timestamp
dnsTime tdns tnow =
    let delta = tdns - fromIntegral tnow
     in if delta > 0x7FFFFFFF -- tdns is in the past?
           then tnow - (0x100000000 - fromIntegral delta)
           else tnow + fromIntegral delta

-- | Helper to find position of RData end, that is, the offset of the first
-- byte /after/ the current RData.
--
rdataEnd :: Int      -- ^ number of bytes left from current position
         -> SGet Int -- ^ end position
rdataEnd lim = (+) lim <$> parserPosition

----------------------------------------------------------------

-- | Encode DNSSEC NSEC type bits
putNsecTypes :: [TYPE] -> SPut
putNsecTypes types = putTypeList $ map fromTYPE types
  where
    putTypeList :: [Word16] -> SPut
    putTypeList ts =
        mconcat [ putWindow (the top8) bot8 |
                  t <- ts,
                  let top8 = fromIntegral t `shiftR` 8,
                  let bot8 = fromIntegral t .&. 0xff,
                  then group by top8
                       using groupWith ]

    putWindow :: Int -> [Int] -> SPut
    putWindow top8 bot8s =
        let blks = maximum bot8s `shiftR` 3
         in putInt8 top8
            <> put8 (1 + fromIntegral blks)
            <> putBits 0 [ (the block, foldl' mergeBits 0 bot8) |
                           bot8 <- bot8s,
                           let block = bot8 `shiftR` 3,
                           then group by block
                                using groupWith ]
      where
        -- | Combine type bits in network bit order, i.e. bit 0 first.
        mergeBits acc b = setBit acc (7 - b.&.0x07)

    putBits :: Int -> [(Int, Word8)] -> SPut
    putBits _ [] = pure mempty
    putBits n ((block, octet) : rest) =
        putReplicate (block-n) 0
        <> put8 octet
        <> putBits (block + 1) rest

-- <https://tools.ietf.org/html/rfc4034#section-4.1>
-- Parse a list of NSEC type bitmaps
--
getNsecTypes :: Int -> SGet [TYPE]
getNsecTypes len = concat <$> sGetMany "NSEC type bitmap" len getbits
  where
    getbits = do
        window <- flip shiftL 8 <$> getInt8
        blocks <- getInt8
        when (blocks > 32) $
            failSGet $ "NSEC bitmap block too long: " ++ show blocks
        concatMap blkTypes. zip [window, window + 8..] <$> getNBytes blocks
      where
        blkTypes (bitOffset, byte) =
            [ toTYPE $ fromIntegral $ bitOffset + i |
              i <- [0..7], byte .&. bit (7-i) /= 0 ]

----------------------------------------------------------------

showSalt :: Opaque -> String
showSalt o = case opaqueToByteString o of
  ""  -> "-"
  bs  -> b16encode bs
