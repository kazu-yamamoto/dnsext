{-# LANGUAGE PatternSynonyms #-}

module DNS.SEC.PubAlg where

import DNS.SEC.Imports
import DNS.Types.Internal

-- https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
newtype PubAlg = PubAlg
    { fromPubAlg :: Word8
    }
    deriving (Eq, Ord)

toPubAlg :: Word8 -> PubAlg
toPubAlg = PubAlg

pattern DELETE :: PubAlg
pattern DELETE = PubAlg 0

pattern RSAMD5 :: PubAlg
pattern RSAMD5 = PubAlg 1

pattern DH :: PubAlg
pattern DH = PubAlg 2

pattern DSA :: PubAlg
pattern DSA = PubAlg 3

pattern RSASHA1 :: PubAlg
pattern RSASHA1 = PubAlg 5

pattern DSA_NSEC3_SHA1 :: PubAlg
pattern DSA_NSEC3_SHA1 = PubAlg 6

pattern RSASHA1_NSEC3_SHA1 :: PubAlg
pattern RSASHA1_NSEC3_SHA1 = PubAlg 7

pattern RSASHA256 :: PubAlg
pattern RSASHA256 = PubAlg 8

pattern RSASHA512 :: PubAlg
pattern RSASHA512 = PubAlg 10

pattern ECC_GOST :: PubAlg
pattern ECC_GOST = PubAlg 12

pattern ECDSAP256SHA256 :: PubAlg
pattern ECDSAP256SHA256 = PubAlg 13

pattern ECDSAP384SHA384 :: PubAlg
pattern ECDSAP384SHA384 = PubAlg 14

pattern ED25519 :: PubAlg
pattern ED25519 = PubAlg 15

pattern ED448 :: PubAlg
pattern ED448 = PubAlg 16

pattern INDIRECT :: PubAlg
pattern INDIRECT = PubAlg 252

pattern PRIVATEDNS :: PubAlg
pattern PRIVATEDNS = PubAlg 253

pattern PRIVATEOID :: PubAlg
pattern PRIVATEOID = PubAlg 254

{- FOURMOLU_DISABLE -}
instance Show PubAlg where
    show DELETE             = "DELETE"
    show RSAMD5             = "RSAMD5"
    show DH                 = "DH"
    show DSA                = "DSA"
    show RSASHA1            = "RSASHA1"
    show DSA_NSEC3_SHA1     = "DSA_NSEC3_SHA1"
    show RSASHA1_NSEC3_SHA1 = "RSASHA1_NSEC3_SHA1"
    show RSASHA256          = "RSASHA256"
    show RSASHA512          = "RSASHA512"
    show ECC_GOST           = "ECC_GOST"
    show ECDSAP256SHA256    = "ECDSAP256SHA256"
    show ECDSAP384SHA384    = "ECDSAP384SHA384"
    show ED25519            = "ED25519"
    show ED448              = "ED448"
    show INDIRECT           = "INDIRECT"
    show PRIVATEDNS         = "PRIVATEDNS"
    show PRIVATEOID         = "PRIVATEOID"
    show (PubAlg n)         = "PubAlg " ++ show n
{- FOURMOLU_ENABLE -}

putPubAlg :: PubAlg -> SPut ()
putPubAlg = put8 . fromPubAlg

getPubAlg :: SGet PubAlg
getPubAlg = toPubAlg <$> get8
