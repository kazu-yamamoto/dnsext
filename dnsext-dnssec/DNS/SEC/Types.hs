{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TransformListComp #-}

module DNS.SEC.Types (
    TYPE (
    RRSIG
  , DS
  , NSEC
  , DNSKEY
  , NSEC3
  , NSEC3PARAM
  , CDS
  , CDNSKEY
  )
  , RD_RRSIG(..)
  , RD_DS(..)
  , RD_NSEC(..)
  , RD_DNSKEY(..)
  , RD_NSEC3(..)
  , RD_NSEC3PARAM(..)
  , RD_CDS(..)
  , RD_CDNSKEY(..)
  , rd_rrsig
  , rd_ds
  , rd_nsec
  , rd_dnskey
  , rd_nsec3
  , rd_nsec3param
  , rd_cds
  , rd_cdnskey
  ) where

import GHC.Exts (the, groupWith)
import DNS.Types
import DNS.Types.Internal

import DNS.SEC.Flags
import DNS.SEC.HashAlg
import DNS.SEC.Imports
import DNS.SEC.PubAlg
import DNS.SEC.PubKey
import DNS.SEC.Time

pattern DS :: TYPE
pattern DS         = TYPE  43 -- RFC 4034
-- | RRSIG (RFC4034)
pattern RRSIG :: TYPE
pattern RRSIG      = TYPE  46 -- RFC 4034
-- | NSEC (RFC4034)
pattern NSEC :: TYPE
pattern NSEC       = TYPE  47 -- RFC 4034
-- | DNSKEY (RFC4034)
pattern DNSKEY :: TYPE
pattern DNSKEY     = TYPE  48 -- RFC 4034
-- | NSEC3 (RFC5155)
pattern NSEC3 :: TYPE
pattern NSEC3      = TYPE  50 -- RFC 5155
-- | NSEC3PARAM (RFC5155)
pattern NSEC3PARAM :: TYPE
pattern NSEC3PARAM = TYPE  51 -- RFC 5155
-- | Child DS (RFC7344)
pattern CDS :: TYPE
pattern CDS        = TYPE  59 -- RFC 7344
-- | DNSKEY(s) the Child wants reflected in DS (RFC7344)
pattern CDNSKEY :: TYPE
pattern CDNSKEY    = TYPE  60 -- RFC 7344

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
    rrsig_type       :: TYPE   -- ^ RRtype of RRset signed
  , rrsig_pubalg     :: PubAlg -- ^ DNSKEY algorithm
  , rrsig_num_labels :: Word8  -- ^ Number of labels signed
  , rrsig_ttl        :: TTL    -- ^ Maximum origin TTL
  , rrsig_expiration :: Int64  -- ^ Time last valid
  , rrsig_inception  :: Int64  -- ^ Time first valid
  , rrsig_key_tag    :: Word16 -- ^ Signing key tag
  , rrsig_zone       :: Domain -- ^ Signing domain
  , rrsig_signature  :: Opaque -- ^ Opaque signature
  } deriving (Eq, Ord, Show)

instance ResourceData RD_RRSIG where
    resourceDataType _ = RRSIG
    putResourceData _ RD_RRSIG{..} = do
        putTYPE    rrsig_type
        putPubAlg  rrsig_pubalg
        put8       rrsig_num_labels
        putSeconds rrsig_ttl
        putDnsTime rrsig_expiration
        putDnsTime rrsig_inception
        put16      rrsig_key_tag
        putDomain  Canonical rrsig_zone
        putOpaque  rrsig_signature
    getResourceData _ lim = do
        -- The signature follows a variable length zone name
        -- and occupies the rest of the RData.  Simplest to
        -- checkpoint the position at the start of the RData,
        -- and after reading the zone name, and subtract that
        -- from the RData length.
        --
        end <- rdataEnd lim
        typ <- getTYPE
        alg <- getPubAlg
        cnt <- get8
        ttl <- getSeconds
        tex <- getDnsTime
        tin <- getDnsTime
        tag <- get16
        dom <- getDomain -- XXX: Enforce no compression?
        pos <- parserPosition
        val <- getOpaque $ end - pos
        return $ RD_RRSIG typ alg cnt ttl tex tin tag dom val

-- | Smart constructor.
rd_rrsig :: TYPE -> PubAlg -> Word8 -> TTL -> Int64 -> Int64 -> Word16 -> Domain -> Opaque -> RData
rd_rrsig a b c d e f g h i = toRData $ RD_RRSIG a b c d e f g h i

----------------------------------------------------------------

-- | Delegation Signer (RFC4034)
data RD_DS = RD_DS {
    ds_key_tag :: Word16
  , ds_pubalg  :: PubAlg
  , ds_hashalg :: DigestAlg
  , ds_digest  :: Opaque
  } deriving (Eq, Ord, Show)

instance ResourceData RD_DS where
    resourceDataType _ = DS
    putResourceData _ RD_DS{..} = do
        put16        ds_key_tag
        putPubAlg    ds_pubalg
        putDigestAlg ds_hashalg
        putOpaque    ds_digest
    getResourceData _ lim =
        RD_DS <$> get16
              <*> getPubAlg
              <*> getDigestAlg
              <*> getOpaque (lim - 4)

-- | Smart constructor.
rd_ds :: Word16 -> PubAlg -> DigestAlg -> Opaque -> RData
rd_ds a b c d = toRData $ RD_DS a b c d

----------------------------------------------------------------

-- | DNSSEC denial of existence NSEC record
data RD_NSEC = RD_NSEC {
    nsecNextDomain :: Domain
  , nsecTypes      :: [TYPE]
  } deriving (Eq, Ord, Show)

instance ResourceData RD_NSEC where
    resourceDataType _ = NSEC
    putResourceData _ RD_NSEC{..} = do
        putDomain Canonical nsecNextDomain
        putNsecTypes nsecTypes
    getResourceData _ len = do
        end <- rdataEnd len
        dom <- getDomain
        pos <- parserPosition
        RD_NSEC dom <$> getNsecTypes (end - pos)

-- | Smart constructor.
rd_nsec :: Domain -> [TYPE] -> RData
rd_nsec a b = toRData $ RD_NSEC a b

----------------------------------------------------------------

-- | DNSKEY (RFC4034)
data RD_DNSKEY = RD_DNSKEY {
    dnskey_flags      :: [DNSKEY_Flag]
  , dnskey_protocol   :: Word8
  , dnskey_pubalg     :: PubAlg
  , dnskey_public_key :: PubKey
  } deriving (Eq, Ord, Show)

instance ResourceData RD_DNSKEY where
    resourceDataType _ = DNSKEY
    putResourceData _ RD_DNSKEY{..} = do
        putDNSKEYflags dnskey_flags
        put8           dnskey_protocol
        putPubAlg      dnskey_pubalg
        putPubKey      dnskey_public_key
    getResourceData _ len = do
        flags  <- getDNSKEYflags
        proto  <- get8
        pubalg <- getPubAlg
        pubkey <- getPubKey pubalg (len - 4)
        return $ RD_DNSKEY flags proto pubalg pubkey

-- | Smart constructor.
rd_dnskey :: [DNSKEY_Flag] -> Word8 -> PubAlg -> PubKey -> RData
rd_dnskey a b c d = toRData $ RD_DNSKEY a b c d

----------------------------------------------------------------

-- | DNSSEC hashed denial of existence (RFC5155)
data RD_NSEC3 = RD_NSEC3 {
    nsec3_hashalg                :: HashAlg
  , nsec3_flags                  :: [NSEC3_Flag]
  , nsec3_iterations             :: Word16
  , nsec3_salt                   :: Opaque
  , nsec3_next_hashed_owner_name :: Opaque
  , nsec3_types                  :: [TYPE]
  } deriving (Eq, Ord, Show)

instance ResourceData RD_NSEC3 where
    resourceDataType _ = NSEC3
    putResourceData _ RD_NSEC3{..} = do
        putHashAlg    nsec3_hashalg
        putNSEC3flags nsec3_flags
        put16         nsec3_iterations
        putLenOpaque  nsec3_salt
        putLenOpaque  nsec3_next_hashed_owner_name
        putNsecTypes  nsec3_types
    getResourceData _ len = do
        dend <- rdataEnd len
        halg <- getHashAlg
        flgs <- getNSEC3flags
        iter <- get16
        salt <- getLenOpaque
        hash <- getLenOpaque
        tpos <- parserPosition
        RD_NSEC3 halg flgs iter salt hash <$> getNsecTypes (dend - tpos)

-- | Smart constructor.
rd_nsec3 :: HashAlg -> [NSEC3_Flag] -> Word16 -> Opaque -> Opaque -> [TYPE] -> RData
rd_nsec3 a b c d e f = toRData $ RD_NSEC3 a b c d e f

----------------------------------------------------------------

-- | NSEC3 zone parameters (RFC5155)
data RD_NSEC3PARAM = RD_NSEC3PARAM {
    nsec3param_hashalg    :: HashAlg
  , nsec3param_flags      :: Word8
  , nsec3param_iterations :: Word16
  , nsec3param_salt       :: Opaque
  } deriving (Eq, Ord, Show)

instance ResourceData RD_NSEC3PARAM where
    resourceDataType _ = NSEC3PARAM
    putResourceData _ RD_NSEC3PARAM{..} = do
        putHashAlg   nsec3param_hashalg
        put8         nsec3param_flags
        put16        nsec3param_iterations
        putLenOpaque nsec3param_salt
    getResourceData _ _ =
        RD_NSEC3PARAM <$> getHashAlg
                      <*> get8
                      <*> get16
                      <*> getLenOpaque

-- | Smart constructor.
rd_nsec3param :: HashAlg -> Word8 -> Word16 -> Opaque -> RData
rd_nsec3param a b c d = toRData $ RD_NSEC3PARAM a b c d

----------------------------------------------------------------

-- | Child DS (RFC7344)
data RD_CDS = RD_CDS {
    cds_key_tag :: Word16
  , cds_pubalg  :: PubAlg
  , cds_hashalg :: DigestAlg
  , cds_digest  :: Opaque
  } deriving (Eq, Ord, Show)

instance ResourceData RD_CDS where
    resourceDataType _ = CDS
    putResourceData _ RD_CDS{..} = do
        put16        cds_key_tag
        putPubAlg    cds_pubalg
        putDigestAlg cds_hashalg
        putOpaque    cds_digest
    getResourceData _ lim =
        RD_CDS <$> get16
               <*> getPubAlg
               <*> getDigestAlg
               <*> getOpaque (lim - 4)

-- | Smart constructor.
rd_cds :: Word16 -> PubAlg -> DigestAlg -> Opaque -> RData
rd_cds a b c d = toRData $ RD_CDS a b c d

----------------------------------------------------------------

-- | Child DNSKEY (RFC7344)
data RD_CDNSKEY = RD_CDNSKEY {
    cdnskey_flags      :: [DNSKEY_Flag]
  , cdnskey_protocol   :: Word8
  , cdnskey_pubalg     :: PubAlg
  , cdnskey_public_key :: PubKey
  } deriving (Eq, Ord, Show)

instance ResourceData RD_CDNSKEY where
    resourceDataType _ = CDNSKEY
    putResourceData _ RD_CDNSKEY{..} = do
        putDNSKEYflags cdnskey_flags
        put8           cdnskey_protocol
        putPubAlg      cdnskey_pubalg
        putPubKey      cdnskey_public_key
    getResourceData _ len = do
        flags  <- getDNSKEYflags
        proto  <- get8
        pubalg <- getPubAlg
        pubkey <- getPubKey pubalg (len - 4)
        return $ RD_CDNSKEY flags proto pubalg pubkey

-- | Smart constructor.
rd_cdnskey :: [DNSKEY_Flag] -> Word8 -> PubAlg -> PubKey -> RData
rd_cdnskey a b c d = toRData $ RD_CDNSKEY a b c d

----------------------------------------------------------------

rdataEnd :: Int      -- ^ number of bytes left from current position
         -> SGet Int -- ^ end position
rdataEnd lim = (+) lim <$> parserPosition

----------------------------------------------------------------

-- | Encode DNSSEC NSEC type bits
putNsecTypes :: [TYPE] -> SPut ()
putNsecTypes types = putTypeList $ map fromTYPE types
  where
    putTypeList :: [Word16] -> SPut ()
    putTypeList ts = sequence_
                [ putWindow (the top8) bot8 |
                  t <- ts,
                  let top8 = fromIntegral t `shiftR` 8,
                  let bot8 = fromIntegral t .&. 0xff,
                  then group by top8
                       using groupWith ]

    putWindow :: Int -> [Int] -> SPut ()
    putWindow top8 bot8s = do
        let blks = maximum bot8s `shiftR` 3
        putInt8 top8
        put8 (1 + fromIntegral blks)
        putBits 0 [ (the block, foldl' mergeBits 0 bot8) |
                    bot8 <- bot8s,
                    let block = bot8 `shiftR` 3,
                    then group by block
                         using groupWith ]
      where
        -- | Combine type bits in network bit order, i.e. bit 0 first.
        mergeBits acc b = setBit acc (7 - b.&.0x07)

    putBits :: Int -> [(Int, Word8)] -> SPut ()
    putBits _ [] = return ()
    putBits n ((block, octet) : rest) = do
        putReplicate (block-n) 0
        put8 octet
        putBits (block + 1) rest

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
