{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UnboxedTuples #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module DNS.SEC.Verify.Verify where

-- GHC packages
import qualified Data.ByteString.Internal as BS
import Data.Map (Map)
import qualified Data.Map as Map
import Foreign.ForeignPtr (withForeignPtr)
import GHC.Exts hiding (TYPE)
import GHC.ST (ST (..), runST)
import System.IO.Unsafe (unsafeDupablePerformIO)

-- dnsext-types
import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque

-- this package
import DNS.SEC.Flags (DNSKEY_Flag (REVOKE, ZONE))
import DNS.SEC.HashAlg
import DNS.SEC.Imports
import DNS.SEC.PubAlg
import DNS.SEC.Time (DNSTime, putDNSTime)
import DNS.SEC.Types
import DNS.SEC.Verify.ECDSA (ecdsaP256SHA, ecdsaP384SHA)
import DNS.SEC.Verify.EdDSA (ed25519, ed448)
import qualified DNS.SEC.Verify.N3SHA as NSEC3
import qualified DNS.SEC.Verify.NSEC as NSEC
import qualified DNS.SEC.Verify.NSEC3 as NSEC3
import qualified DNS.SEC.Verify.NSECxRange as NRange
import DNS.SEC.Verify.RSA (rsaSHA1, rsaSHA256, rsaSHA512)
import qualified DNS.SEC.Verify.SHA as DS
import DNS.SEC.Verify.Types

keyTag :: RD_DNSKEY -> Word16
keyTag dnskey = keyTagFromBS $ runBuilder (resourceDataSize dnskey) $ putResourceData Canonical dnskey

{- FOURMOLU_DISABLE -}
-- KeyTag algorithm from https://datatracker.ietf.org/doc/html/rfc4034#appendix-B
keyTagFromBS :: ByteString -> Word16
keyTagFromBS (BS.BS ftpr (I# len#)) =
    fromIntegral $ unsafeDupablePerformIO $ withForeignPtr ftpr $ return . go 0 0
  where
    go :: Int -> Word -> Ptr Word8 -> Word
    go (I# i0) (W# ac0) (Ptr ptr0#) = runST $ ST $ loop i0 ac0
      where
        loop :: Int# -> Word# -> State# d -> (# State# d, Word #)  {- unboxed-word calculation -}
        loop i0# ac0# s = case len# -# i0# of
            0# -> (# s, final ac0# #)
            1# -> case readWord8OffAddr# ptr0# i0# s of
                      (# s, key0# #) ->
                          let ac1# = ac0# `plusWord#` (word8ToWord# key0# `uncheckedShiftL#` 8#)
                          in  (# s, final ac1# #)
            _  -> case readWord8OffAddr# ptr0# i0# s of
                      (# s, key0# #) -> case readWord8OffAddr# ptr0# (i0# +# 1#) s of
                          (# s, key1# #) ->
                              let ac2# = ac0# `plusWord#` (word8ToWord# key0# `uncheckedShiftL#` 8#)
                                              `plusWord#` word8ToWord# key1#
                                  i2# = i0# +# 2#
                              in  loop i2# ac2# s
    final :: Word# -> Word
    final ac# = W# ((ac# `plusWord#` ((ac# `uncheckedShiftRL#` 16#) `and#` 0xFFFF##)) `and#` 0xFFFF##)
{- FOURMOLU_ENABLE -}

checkKeyTag :: RD_DNSKEY -> Word16 -> Either String ()
checkKeyTag dnskey@RD_DNSKEY{..} tag = do
    let keyTag_ = keyTag dnskey
    when (dnskey_pubalg == RSAMD5) $
        Left "checkKeyTag: not implemented key-tag computation for RSAMD5"
    unless (keyTag_ == tag) $
        Left $
            "checkKeyTag: Key Tag mismatch between DNSKEY and RRSIG: "
                ++ show keyTag_
                ++ " =/= "
                ++ show tag

{- FOURMOLU_DISABLE -}
pubkeyDicts :: Map PubAlg RRSIGImpl
pubkeyDicts =
    Map.fromList
        [ (RSASHA1,             rsaSHA1)
        , (RSASHA1_NSEC3_SHA1,  rsaSHA1)  {- https://datatracker.ietf.org/doc/html/rfc5155#section-2 -}
        , (RSASHA256,           rsaSHA256)
        , (RSASHA512,           rsaSHA512)
        , (ECDSAP256SHA256,     ecdsaP256SHA)
        , (ECDSAP384SHA384,     ecdsaP384SHA)
        , (ED25519,             ed25519)
        , (ED448,               ed448)
        ]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
supportedDNSKEY :: RD_DNSKEY -> Bool
supportedDNSKEY RD_DNSKEY{..} =
   ZONE `elem` dnskey_flags       &&  {- https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1 -}
   REVOKE `notElem` dnskey_flags  &&  {- https://datatracker.ietf.org/doc/html/rfc5011#section-2.1 -}
   dnskey_protocol == 3           &&  {- https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.2 -}
   Map.member dnskey_pubalg pubkeyDicts
{- FOURMOLU_ENABLE -}

---

putRRSIGHeader :: RD_RRSIG -> Builder ()
putRRSIGHeader RD_RRSIG{..} wbuf ref = do
    put16 wbuf $ fromTYPE rrsig_type
    putPubAlg rrsig_pubalg wbuf ref
    put8 wbuf rrsig_num_labels
    putSeconds rrsig_ttl wbuf ref
    putDNSTime rrsig_expiration wbuf ref
    putDNSTime rrsig_inception wbuf ref
    put16 wbuf rrsig_key_tag
    putDomain Canonical rrsig_zone wbuf ref

sizeRRSIGHeader :: RD_RRSIG -> Int
sizeRRSIGHeader RD_RRSIG{..} =
    2 {- TYPE -}
        + 1 {- PubAlg -}
        + 1 {- num_labels -}
        + 4 {- Seconds -}
        + 4 {- DNSTime -}
        + 4 {- DNSTime -}
        + 2 {- KeyTag -}
        + domainSize rrsig_zone

verifyRRSIGwith
    :: RRSIGImpl
    -> DNSTime
    -> RD_DNSKEY
    -> RD_RRSIG
    -> Domain
    -> TYPE
    -> CLASS
    -> [(Int, Builder ())]
    -> Either String ()
verifyRRSIGwith RRSIGImpl{..} now RD_DNSKEY{..} rrsig@RD_RRSIG{..} rrset_name rrset_type rrset_class sortedRDatas' = do
    unless (ZONE `elem` dnskey_flags) $
        {- https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1
           "If bit 7 has value 0, then the DNSKEY record holds some other type of DNS public key
            and MUST NOT be used to verify RRSIGs that cover RRsets." -}
        Left "verifyRRSIGwith: ZONE flag is not set for DNSKEY flags"
    unless (REVOKE `notElem` dnskey_flags) $
        {- https://datatracker.ietf.org/doc/html/rfc5011#section-2.1
         "Once the resolver sees the REVOKE bit, it MUST NOT use this key as a trust anchor or for any other purpose except
          to validate the RRSIG it signed over the DNSKEY RRSet specifically for the purpose of validating the revocation." -}
        Left "verifyRRSIGwith: REVOKE flag is set for DNSKEY flags"
    unless (dnskey_protocol == 3) $
        {- https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.2  "The Protocol Field MUST have value 3" -}
        Left $
            "verifyRRSIGwith: protocol number of DNSKEY is not 3: " ++ show dnskey_protocol
    unless (dnskey_pubalg == rrsig_pubalg) $
        Left $
            "verifyRRSIGwith: pubkey algorithm mismatch between DNSKEY and RRSIG: "
                ++ show dnskey_pubalg
                ++ " =/= "
                ++ show rrsig_pubalg

    unless (numLabels rrset_name >= fromIntegral rrsig_num_labels) $
        Left $
            "verifyRRSIGwith: number of rrname labels is too small: "
                ++ ("rrname-labels=" ++ show (numLabels rrset_name))
                ++ " < "
                ++ ("rrsig-labels=" ++ show rrsig_num_labels)
    unless (rrsig_inception <= now && now < rrsig_expiration) $
        Left $
            "verifyRRSIGwith: not valid period of RRSIG: to be valid, time "
                ++ show now
                ++ " must be between "
                ++ show rrsig_inception
                ++ " and "
                ++ show rrsig_expiration

    unless (rrset_type == rrsig_type) $
        Left $
            "verifyRRSIGwith: TYPE mismatch between RRset and RRSIG: "
                ++ show rrset_type
                ++ " =/= "
                ++ show rrsig_type

    pubkey <- rrsigIGetKey dnskey_public_key
    sig <- rrsigIGetSig rrsig_signature
    {- "Reconstructing the Signed Data"
       https://datatracker.ietf.org/doc/html/rfc4035#section-5.3.2
       RR(i) = name | type | class | OrigTTL | RDATA length | RDATA -}
    let (rlengths, sortedRDatas) = unzip sortedRDatas'
        putRRH wbuf ref = do
            putDomainRFC1035 Canonical rrset_name wbuf ref
            putTYPE rrset_type wbuf ref
            putCLASS rrset_class wbuf ref
            putSeconds rrsig_ttl wbuf ref
        putRRS wbuf ref = do
            putRRSIGHeader rrsig wbuf ref
            mapM_ (\io -> putRRH wbuf ref >> io wbuf ref) sortedRDatas
        sizeRR rlen =
            domainSize rrset_name
                + 2 {- TYPE -}
                + 2 {- CLASS -}
                + 4 {- seconds -}
                + rlen
        sizeStr = sum $ sizeRRSIGHeader rrsig : map sizeRR rlengths
        str = runBuilder sizeStr putRRS
    {- `Data.List.sort` is linear for sorted case -}
    good <- rrsigIVerify pubkey sig str
    unless good $ Left "verifyRRSIGwith: rejected on verification"

{- RFC 4034 Section 6.3: Canonical RR Ordering within an RRset
   https://datatracker.ietf.org/doc/html/rfc4034#section-6.3
   "RRs with the same owner name,
    class, and type are sorted by treating the RDATA portion of the
    canonical form of each RR as a left-justified unsigned octet sequence" -}
sortRDataCanonical :: [ResourceRecord] -> [((Int, Builder ()), ResourceRecord)]
sortRDataCanonical rrs =
    {- sortOn "RDATA portion of the canonical form" without RDATA length -}
    map snd $ sortOn fst withWires
  where
    withWires =
        [ (runBuilder sz sput, ((2 {- len size -} + sz, with16Length sput), rr))
        | rr <- rrs
        , let sput = putRData Canonical $ rdata rr
              sz = rdataSize $ rdata rr
        ]

{- FOURMOLU_DISABLE -}
{- assume sorted input. generalized RRset with CPS -}
canonicalRRsetSorted'
    :: [ResourceRecord]
    -> (String -> a) -> (Domain -> TYPE -> CLASS -> TTL -> [RData] -> a) -> a
canonicalRRsetSorted' rrs leftK rightK = either leftK id $ do
    (hd, xs) <- maybe (Left "canonicalRRsetSorted: require non-empty RRset") Right $ uncons rrs
    let eqhd x = ((==) `on` rrname)  hd x  &&
                 ((==) `on` rrtype)  hd x  &&
                 ((==) `on` rrclass) hd x
    unless (all eqhd xs) $
        Left "canonicalRRsetSorted: requires same ( rrname, rrtype, rrclass )"
    let rds = [rdata rr | rr <- rrs]
    unless (all ((== 1) . length) $ group rds) $
        Left "canonicalRRsetSorted: requires unique RData set"
    return $ rightK (rrname hd) (rrtype hd) (rrclass hd) (rrttl hd) rds
{- FOURMOLU_ENABLE -}

canonicalRRsetSorted
    :: [ResourceRecord]
    -> Either String ((Domain -> TYPE -> CLASS -> TTL -> [RData] -> a) -> a)
canonicalRRsetSorted rrs = canonicalRRsetSorted' rrs Left (\n ty cls ttl rd -> Right $ \h -> h n ty cls ttl rd)

{- FOURMOLU_DISABLE -}
{- generalized RRset with CPS -}
canonicalRRset
    :: [ResourceRecord]
    -> (String -> a) -> ((Domain -> TYPE -> CLASS -> TTL -> [RData] -> a) -> a)
canonicalRRset rrs = canonicalRRsetSorted' [rr | (_, rr) <- sortRDataCanonical rrs]
{- FOURMOLU_ENABLE -}

verifyRRSIGsorted
    :: DNSTime
    -> RD_DNSKEY
    -> RD_RRSIG
    -> Domain
    -> TYPE
    -> CLASS
    -> [(Int, Builder ())]
    -> Either String ()
verifyRRSIGsorted now dnskey rrsig name typ cls sortedRDatas =
    maybe (Left $ "verifyRRSIGsorted: unsupported algorithm: " ++ show alg) verify $
        Map.lookup alg pubkeyDicts
  where
    alg = dnskey_pubalg dnskey
    verify impl = verifyRRSIGwith impl now dnskey rrsig name typ cls sortedRDatas

{- FOURMOLU_DISABLE -}
verifyRRSIG
    :: DNSTime
    -> Domain
    -> RD_DNSKEY
    -> Domain
    -> RD_RRSIG
    -> [ResourceRecord]
    -> Either String ()
verifyRRSIG now zone dnskey owner rrsig@RD_RRSIG{..} rrs = do
    unless (rrsig_zone == zone) $
        Left $ "verifyRRSIG: RRSIG zone mismatch: "
            ++ show rrsig_zone
            ++ " =/= "
            ++ show zone
    {- The RRset MUST be sorted in canonical order.
       https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.8.1 -}
    let (sortedRDatas, sortedRRs) = unzip $ sortRDataCanonical rrs
    canonicalRRsetSorted' sortedRRs Left $
        \rrset_dom typ cls _ttl _rds -> do
            unless (rrset_dom == owner) $
                Left $ "verifyRRSIG: RRset domain mismatch with owner-domain: "
                    ++ show rrset_dom
                    ++ " =/= "
                    ++ show owner
            verifyRRSIGsorted now dnskey rrsig rrset_dom typ cls sortedRDatas
{- FOURMOLU_ENABLE -}

supportedRRSIG :: RD_RRSIG -> Bool
supportedRRSIG RD_RRSIG{..} = Map.member rrsig_pubalg pubkeyDicts

---

verifyDSwith :: DSImpl -> Domain -> RD_DNSKEY -> RD_DS -> Either String ()
verifyDSwith DSImpl{..} owner dnskey@RD_DNSKEY{..} RD_DS{..} = do
    unless (ZONE `elem` dnskey_flags) $
        {- https://datatracker.ietf.org/doc/html/rfc4034#section-5.2
           "The DNSKEY RR referred  to in the DS RR MUST be a DNSSEC zone key." -}
        Left "verifyDSwith: ZONE flag is not set for DNSKEY flags"
    unless (dnskey_pubalg == ds_pubalg) $
        Left $
            "verifyDSwith: pubkey algorithm mismatch between DNSKEY and DS: "
                ++ show dnskey_pubalg
                ++ " =/= "
                ++ show ds_pubalg
    let dnskeyBS = runBuilder (resourceDataSize dnskey) $ putResourceData Canonical dnskey
        digest = dsIGetDigest (runBuilder (domainSize owner) (putDomain Canonical owner) <> dnskeyBS)
        ds_digest' = Opaque.toByteString ds_digest
    unless (dsIVerify digest ds_digest') $
        Left "verifyDSwith: rejected on verification"

dsDicts :: Map DigestAlg DSImpl
dsDicts =
    Map.fromList
        [ (SHA1, DS.sha1)
        , (SHA256, DS.sha256)
        , (SHA384, DS.sha384)
        ]

verifyDS :: Domain -> RD_DNSKEY -> RD_DS -> Either String ()
verifyDS owner dnskey ds =
    maybe (Left $ "verifyDS: unsupported algorithm: " ++ show alg) verify $
        Map.lookup alg dsDicts
  where
    alg = ds_digestalg ds
    verify impl = verifyDSwith impl owner dnskey ds

{- FOURMOLU_DISABLE -}
supportedDS :: RD_DS -> Bool
supportedDS RD_DS{..} =
    Map.member ds_digestalg dsDicts  &&
    Map.member ds_pubalg pubkeyDicts
{- FOURMOLU_ENABLE -}

---

hashNSEC3with' :: NSEC3Impl -> Word16 -> Opaque -> Domain -> Opaque
hashNSEC3with' NSEC3Impl{..} iter osalt domain =
    Opaque.fromByteString $ recurse iter
  where
    recurse i
        | i <= 0 = step $ runBuilder (domainSize domain) $ putDomain Canonical domain
        | otherwise = step $ recurse $ i - 1
    step = nsec3IGetBytes . nsec3IGetHash . (<> salt)
    salt = Opaque.toByteString osalt

hashNSEC3with :: NSEC3Impl -> RD_NSEC3 -> Domain -> Opaque
hashNSEC3with impl RD_NSEC3{..} domain =
    hashNSEC3with' impl nsec3_iterations nsec3_salt domain

{- `nsec3param_flags` should be checked outside.
   https://datatracker.ietf.org/doc/html/rfc5155#section-4.1.2
   "NSEC3PARAM RRs with a Flags field value other than zero MUST be ignored." -}
hashNSEC3PARAMwith :: NSEC3Impl -> RD_NSEC3PARAM -> Domain -> Opaque
hashNSEC3PARAMwith impl RD_NSEC3PARAM{..} domain =
    hashNSEC3with' impl nsec3param_iterations nsec3param_salt domain

nsec3Dicts :: Map HashAlg NSEC3Impl
nsec3Dicts =
    Map.fromList
        [ (Hash_SHA1, NSEC3.n3sha1)
        ]

---

hashNSEC3 :: RD_NSEC3 -> Domain -> Either String Opaque
hashNSEC3 nsec3 domain =
    maybe (Left $ "hashNSEC3: unsupported algorithm: " ++ show alg) (Right . hash) $
        Map.lookup alg nsec3Dicts
  where
    alg = nsec3_hashalg nsec3
    hash impl = hashNSEC3with impl nsec3 domain

hashNSEC3PARAM :: RD_NSEC3PARAM -> Domain -> Either String Opaque
hashNSEC3PARAM nsec3p domain =
    maybe
        (Left $ "hashNSEC3PARAM: unsupported algorithm: " ++ show alg)
        (Right . hash)
        $ Map.lookup alg nsec3Dicts
  where
    alg = nsec3param_hashalg nsec3p
    hash impl = hashNSEC3PARAMwith impl nsec3p domain

---

zipSigsNSEC3 :: [ResourceRecord] -> (String -> a) -> ([(ResourceRecord, NSEC3_Range, [(RD_RRSIG, TTL)])] -> a) -> a
zipSigsNSEC3 = NRange.zipSigsets NSEC3.rangeImpl

getNSEC3Result :: NSEC3.Logic a -> Domain -> [NSEC3_Range] -> Domain -> Either String a
getNSEC3Result hl zone cs qname =
    withImpls $ \ps -> NSEC3.getResult hl zone [(c, hashNSEC3with impl nsec3) | (impl, c@(_, nsec3)) <- ps] qname
  where
    withImpls h = h =<< mapM addImpl cs
    addImpl r@(_, nsec3) = do
        let alg = nsec3_hashalg nsec3
        impl <- maybe (Left $ "NSEC3: unsupported algorithm: " ++ show alg) Right $ Map.lookup alg nsec3Dicts
        return (impl, r)

nameErrorNSEC3 :: Domain -> [NSEC3_Range] -> Domain -> Either String NSEC3_NameError
nameErrorNSEC3 = getNSEC3Result NSEC3.get_nameError

noDataNSEC3 :: Domain -> [NSEC3_Range] -> Domain -> TYPE -> Either String NSEC3_NoData
noDataNSEC3 zone ranges qname qtype = getNSEC3Result (NSEC3.get_noData qtype) zone ranges qname

unsignedDelegationNSEC3 :: Domain -> [NSEC3_Range] -> Domain -> Either String NSEC3_UnsignedDelegation
unsignedDelegationNSEC3 = getNSEC3Result NSEC3.get_unsignedDelegation

wildcardExpansionNSEC3 :: Domain -> [NSEC3_Range] -> Domain -> Either String NSEC3_WildcardExpansion
wildcardExpansionNSEC3 = getNSEC3Result NSEC3.get_wildcardExpansion

wildcardNoDataNSEC3 :: Domain -> [NSEC3_Range] -> Domain -> TYPE -> Either String NSEC3_WildcardNoData
wildcardNoDataNSEC3 zone ranges qname qtype = getNSEC3Result (NSEC3.get_wildcardNoData qtype) zone ranges qname

detectNSEC3 :: Domain -> [NSEC3_Range] -> Domain -> TYPE -> Either String NSEC3_Result
detectNSEC3 zone ranges qname qtype = getNSEC3Result (NSEC3.detect qtype) zone ranges qname

---

zipSigsNSEC :: [ResourceRecord] -> (String -> a) -> ([(ResourceRecord, NSEC_Range, [(RD_RRSIG, TTL)])] -> a) -> a
zipSigsNSEC = NRange.zipSigsets NSEC.rangeImpl

---

nameErrorNSEC :: Domain -> [NSEC_Range] -> Domain -> Either String NSEC_NameError
nameErrorNSEC = NSEC.getResult NSEC.get_nameError

noDataNSEC :: Domain -> [NSEC_Range] -> Domain -> TYPE -> Either String NSEC_NoData
noDataNSEC zone ranges qname qtype = NSEC.getResult (NSEC.get_noData qtype) zone ranges qname

unsignedDelegationNSEC :: Domain -> [NSEC_Range] -> Domain -> Either String NSEC_UnsignedDelegation
unsignedDelegationNSEC zone = NSEC.getResult (NSEC.get_unsignedDelegation zone) zone

wildcardExpansionNSEC :: Domain -> [NSEC_Range] -> Domain -> Either String NSEC_WildcardExpansion
wildcardExpansionNSEC = NSEC.getResult NSEC.get_wildcardExpansion

wildcardNoDataNSEC :: Domain -> [NSEC_Range] -> Domain -> TYPE -> Either String NSEC_WildcardNoData
wildcardNoDataNSEC zone ranges qname qtype = NSEC.getResult (NSEC.get_wildcardNoData qtype) zone ranges qname

detectNSEC :: Domain -> [NSEC_Range] -> Domain -> TYPE -> Either String NSEC_Result
detectNSEC zone ranges qname qtype = NSEC.getResult (NSEC.detect zone qtype) zone ranges qname
