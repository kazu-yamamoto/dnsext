{-# LANGUAGE PatternSynonyms #-}

module DNS.SEC.HashAlg where

import DNS.Types.Internal

import DNS.SEC.Imports

-- https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml

data HashAlg = HashAlg {
    fromHashAlg :: Word8
  } deriving (Eq, Ord)

toHashAlg :: Word8 -> HashAlg
toHashAlg = HashAlg

pattern SHA1   :: HashAlg
pattern SHA1    = HashAlg 1

pattern SHA256 :: HashAlg
pattern SHA256  = HashAlg 2

pattern GOST   :: HashAlg
pattern GOST    = HashAlg 3

pattern SHA384 :: HashAlg
pattern SHA384  = HashAlg 4

instance Show HashAlg where
    show SHA1        = "SHA1"
    show SHA256      = "SHA256"
    show GOST        = "GOST"
    show SHA384      = "SHA384"
    show (HashAlg n) = "HashAlg " ++ show n

putHashAlg :: HashAlg -> SPut
putHashAlg = put8 . fromHashAlg

getHashAlg :: SGet HashAlg
getHashAlg = toHashAlg <$> get8
