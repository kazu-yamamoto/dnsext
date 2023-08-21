{-# LANGUAGE ExistentialQuantification #-}

module DNS.SEC.Verify.Types where

-- dnsext-types

-- this package
import DNS.SEC.Imports
import DNS.SEC.PubKey
import DNS.SEC.Types (RD_NSEC, RD_NSEC3)
import DNS.Types

data RRSIGImpl = forall pubkey sig.
      RRSIGImpl
    { rrsigIGetKey :: PubKey -> Either String pubkey
    , rrsigIGetSig :: Opaque -> Either String sig
    , rrsigIVerify :: pubkey -> sig -> ByteString -> Either String Bool
    }

data DSImpl = forall digest.
      DSImpl
    { dsIGetDigest :: ByteString -> digest
    , dsIVerify :: digest -> ByteString -> Bool
    }

data NSEC3Impl = forall hash.
      NSEC3Impl
    { nsec3IGetHash :: ByteString -> hash
    , nsec3IGetBytes :: hash -> ByteString
    }

---

-- | owner name and NSEC3 rdata express hashed domain-name range
type NSEC3_Range = (Domain, RD_NSEC3)

-- | range and qname which is owner of it or covered by it
type NSEC3_Witness = (NSEC3_Range, Domain)

{- FOURMOLU_DISABLE -}
data NSEC3_NameError =
    NSEC3_NameError
    { nsec3_nameError_closest_match :: NSEC3_Witness
    , nsec3_nameError_next_closer_cover :: NSEC3_Witness
    , nsec3_nameError_wildcard_cover :: NSEC3_Witness
    } {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.1 -}
    deriving Show

data NSEC3_NoData =
    NSEC3_NoData
    { nsec3_noData_closest_match :: NSEC3_Witness
    } {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.2
         https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.6 -}
    deriving Show

data NSEC3_UnsignedDelegation =
    NSEC3_UnsignedDelegation
    { nsec3_unsignedDelegation_closest_match :: NSEC3_Witness
    , nsec3_unsignedDelegation_next_closer_cover :: NSEC3_Witness
    } {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.3 -}
    deriving Show

data NSEC3_WildcardExpansion =
    NSEC3_WildcardExpansion
    { nsec3_wildcardExpansion_next_closer_cover :: NSEC3_Witness
    } {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.4 -}
    deriving Show

data NSEC3_WildcardNoData =
    NSEC3_WildcardNoData
    { nsec3_wildcardNodata_closest_match :: NSEC3_Witness
    , nsec3_wildcardNodata_next_closer_cover :: NSEC3_Witness
    , nsec3_wildcardNodata_wildcard_match :: NSEC3_Witness
    } {- https://datatracker.ietf.org/doc/html/rfc5155#appendix-B.5 -}
    deriving Show
{- FOURMOLU_ENABLE -}

data NSEC3_Result
    = N3R_NameError NSEC3_NameError
    | N3R_NoData NSEC3_NoData
    | N3R_UnsignedDelegation NSEC3_UnsignedDelegation
    | N3R_WildcardExpansion NSEC3_WildcardExpansion
    | N3R_WildcardNoData NSEC3_WildcardNoData
    deriving (Show)

---

type NSEC_Range = (Domain, RD_NSEC)

type NSEC_Witness = (NSEC_Range, Domain)

data NSEC_Result
    = NSECResult_NameError
        { nsec_qname_cover :: NSEC_Witness
        , nsec_wildcard_cover :: NSEC_Witness
        } {- https://datatracker.ietf.org/doc/html/rfc4035#appendix-B.2 -}
    | NSECResult_NoData
        { nsec_qname_match :: NSEC_Witness
        } {- https://datatracker.ietf.org/doc/html/rfc4035#appendix-B.3 -}
    | NSECResult_UnsignedDelegation
        { nsec_ns_qname_cover :: NSEC_Witness
        } {- https://datatracker.ietf.org/doc/html/rfc4035#appendix-B.5 -}
    | NSECResult_WildcardExpansion
        { nsec_qname_cover :: NSEC_Witness
        } {- https://datatracker.ietf.org/doc/html/rfc4035#appendix-B.6 -}
    | NSECResult_WildcardNoData
        { nsec_qname_cover :: NSEC_Witness
        , nsec_wildcard_match :: NSEC_Witness
        } {- https://datatracker.ietf.org/doc/html/rfc4035#appendix-B.7 -}
    deriving (Show)
