{-# LANGUAGE PatternSynonyms #-}

module DNS.SEC.HashAlg where

import DNS.SEC.Imports
import DNS.Types.Internal

-- https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml

newtype DigestAlg = DigestAlg
    { fromDigestAlg :: Word8
    }
    deriving (Eq, Ord)

toDigestAlg :: Word8 -> DigestAlg
toDigestAlg = DigestAlg

pattern SHA1 :: DigestAlg
pattern SHA1 = DigestAlg 1

pattern SHA256 :: DigestAlg
pattern SHA256 = DigestAlg 2

pattern GOST :: DigestAlg
pattern GOST = DigestAlg 3

pattern SHA384 :: DigestAlg
pattern SHA384 = DigestAlg 4

{- FOURMOLU_DISABLE -}
instance Show DigestAlg where
    show SHA1          = "SHA1"
    show SHA256        = "SHA256"
    show GOST          = "GOST"
    show SHA384        = "SHA384"
    show (DigestAlg n) = "DigestAlg " ++ show n
{- FOURMOLU_ENABLE -}

putDigestAlg :: DigestAlg -> SPut ()
putDigestAlg = put8 . fromDigestAlg

getDigestAlg :: SGet DigestAlg
getDigestAlg rbuf _ = toDigestAlg <$> get8 rbuf

-- https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml

newtype HashAlg = HashAlg
    { fromHashAlg :: Word8
    }
    deriving (Eq, Ord)

toHashAlg :: Word8 -> HashAlg
toHashAlg = HashAlg

pattern Hash_SHA1 :: HashAlg
pattern Hash_SHA1 = HashAlg 1

instance Show HashAlg where
    show Hash_SHA1 = "SHA1"
    show (HashAlg n) = "HashAlg " ++ show n

putHashAlg :: HashAlg -> SPut ()
putHashAlg = put8 . fromHashAlg

getHashAlg :: SGet HashAlg
getHashAlg rbuf _ = toHashAlg <$> get8 rbuf
