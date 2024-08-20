{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.WitnessInfo where

-- dnsext-*
import DNS.SEC
import DNS.SEC.Verify.Types
import DNS.Types
import qualified DNS.Types.Opaque as Opaque

witnessInfoNSEC3 :: NSECxWitnessInfo NSEC3_Witness n => n -> [String]
witnessInfoNSEC3 = witnessInfo showMatchNSEC3 showCoverNSEC3

witnessInfoNSEC :: NSECxWitnessInfo NSEC_Witness n => n -> [String]
witnessInfoNSEC = witnessInfo showMatchNSEC showCoverNSEC

---

showMatchNSEC3 :: NSEC3_Witness -> String
showMatchNSEC3 = showMatch showN3 getUpperN3 nsec3_types

showCoverNSEC3 :: NSEC3_Witness -> String
showCoverNSEC3 = showCover showN3 getUpperN3 nsec3_types

showMatchNSEC :: NSEC_Witness -> String
showMatchNSEC = showMatch show nsec_next_domain nsec_types

showCoverNSEC :: NSEC_Witness -> String
showCoverNSEC = showCover show nsec_next_domain nsec_types

showMatch :: (Domain -> String) -> (rd -> Domain) -> (rd -> [TYPE]) -> ((Domain, rd), Domain) -> String
showMatch showN getU getT ((lower, rd), name) =
    "match: " ++ showN name ++ " with (" ++ show lower ++ ", " ++ show (getU rd) ++ ") " ++ show (getT rd)

showCover :: (Domain -> String) -> (rd -> Domain) -> (rd -> [TYPE]) -> ((Domain, rd), Domain) -> String
showCover showN getU getT ((lower, rd), name) =
    "cover: " ++ showN name ++ " covered by (" ++ show lower ++ ", " ++ show (getU rd) ++ ") " ++ show (getT rd)

showN3 :: Domain -> String
showN3 name = "H(" ++ show name ++ ")"

getUpperN3 :: RD_NSEC3 -> Domain
getUpperN3 = fromRepresentation . Opaque.toBase32Hex . nsec3_next_hashed_owner_name

---

class NSECxWitnessInfo w n where
    witnessInfo :: (w -> a) -> (w -> a) -> n -> [a]

{- FOURMOLU_DISABLE -}
instance NSECxWitnessInfo NSEC3_Witness NSEC3_NameError where
    witnessInfo m c NSEC3_NameError{..} =
        [ m nsec3_nameError_closest_match
        , c nsec3_nameError_next_closer_cover
        , c nsec3_nameError_wildcard_cover ]

instance NSECxWitnessInfo NSEC3_Witness NSEC3_NoData where
    witnessInfo m _ NSEC3_NoData{..} =
        [ m nsec3_noData_closest_match ]

instance NSECxWitnessInfo NSEC3_Witness NSEC3_UnsignedDelegation where
    witnessInfo m c NSEC3_UnsignedDelegation{..} =
        [ m nsec3_unsignedDelegation_closest_match
        , c nsec3_unsignedDelegation_next_closer_cover ]

instance NSECxWitnessInfo NSEC3_Witness NSEC3_WildcardExpansion where
    witnessInfo _ c NSEC3_WildcardExpansion{..} =
        [ c nsec3_wildcardExpansion_next_closer_cover ]

instance NSECxWitnessInfo NSEC3_Witness NSEC3_WildcardNoData where
    witnessInfo m c NSEC3_WildcardNoData{..} =
        [ m nsec3_wildcardNodata_closest_match
        , c nsec3_wildcardNodata_next_closer_cover
        , m nsec3_wildcardNodata_wildcard_match ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
instance NSECxWitnessInfo NSEC_Witness NSEC_NameError where
    witnessInfo _ c NSEC_NameError{..} =
        [ c nsec_nameError_qname_cover
        , c nsec_nameError_wildcard_cover ]

instance NSECxWitnessInfo NSEC_Witness NSEC_NoData where
    witnessInfo m _ NSEC_NoData{..} =
        [ m nsec_noData_qname_match ]

instance NSECxWitnessInfo NSEC_Witness NSEC_UnsignedDelegation where
    witnessInfo _ c NSEC_UnsignedDelegation{..} =
        [ c nsec_unsignedDelegation_ns_qname_cover ]

instance NSECxWitnessInfo NSEC_Witness NSEC_WildcardExpansion where
    witnessInfo _ c NSEC_WildcardExpansion{..} =
        [ c nsec_wildcardExpansion_qname_cover ]

instance NSECxWitnessInfo NSEC_Witness NSEC_WildcardNoData where
    witnessInfo m c NSEC_WildcardNoData{..} =
        [ c nsec_wildcardNoData_qname_cover
        , m nsec_wildcardNoData_wildcard_match ]
{- FOURMOLU_ENABLE -}
