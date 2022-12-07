{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.Verify where

import Data.Map (Map)
import qualified Data.Map as Map
import qualified Data.ByteString as BS

-- dnsext-types
import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque

-- this package
import DNS.SEC.Imports
import DNS.SEC.Time (putDnsTime)
import DNS.SEC.Flags (DNSKEY_Flag (ZONE, REVOKE))
import DNS.SEC.PubAlg
import DNS.SEC.HashAlg
import DNS.SEC.Types (RD_RRSIG(..), RD_DNSKEY(..), RD_DS (..))

import DNS.SEC.Verify.Types
import DNS.SEC.Verify.RSA (rsaSHA1, rsaSHA256, rsaSHA512)
import DNS.SEC.Verify.ECDSA (ecdsaP256SHA, ecdsaP384SHA)
import DNS.SEC.Verify.EdDSA (ed25519, ed448)
import qualified DNS.SEC.Verify.SHA as DS


keyTag :: RD_DNSKEY -> Word16
keyTag = keyTagFromBS . runSPut . putResourceData Canonical

-- KeyTag algorithm from https://datatracker.ietf.org/doc/html/rfc4034#appendix-B
keyTagFromBS :: ByteString -> Word16
keyTagFromBS bs = fromIntegral $ (sumK + sumK `shiftR` 16 .&. 0xFFFF) .&. 0xFFFF
  where
    addHigh w8 = (+ (fromIntegral w8 `shiftL` 8))
    addLow  w8 = (+  fromIntegral w8)
    loopOps = zipWith ($) (cycle [addHigh, addLow]) (BS.unpack bs)
    sumK :: Int
    sumK = foldr ($) 0 loopOps

---

putRRSIGHeader :: RD_RRSIG -> SPut ()
putRRSIGHeader RD_RRSIG{..} = do
    put16    $ fromTYPE rrsig_type
    putPubAlg  rrsig_pubalg
    put8       rrsig_num_labels
    putSeconds rrsig_ttl
    putDnsTime rrsig_expiration
    putDnsTime rrsig_inception
    put16      rrsig_key_tag
    putDomain Canonical rrsig_zone

verifyRRSIGwith :: RRSIGImpl -> RD_DNSKEY -> RD_RRSIG -> ResourceRecord -> Either String ()
verifyRRSIGwith RRSIGImpl{..} dnskey@RD_DNSKEY{..} rrsig@RD_RRSIG{..} rr = do
  unless (ZONE `elem` dnskey_flags) $
    {- https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1
       "If bit 7 has value 0, then the DNSKEY record holds some other type of DNS public key
        and MUST NOT be used to verify RRSIGs that cover RRsets." -}
    Left   "verifyRRSIGwith: ZONE flag is not set for DNSKEY flags"
  unless (REVOKE `notElem` dnskey_flags) $
    {- https://datatracker.ietf.org/doc/html/rfc5011#section-2.1
     "Once the resolver sees the REVOKE bit, it MUST NOT use this key as a trust anchor or for any other purpose except
      to validate the RRSIG it signed over the DNSKEY RRSet specifically for the purpose of validating the revocation." -}
    Left   "verifyRRSIGwith: REVOKE flag is set for DNSKEY flags"
  unless (dnskey_protocol == 3) $
    {- https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.2  "The Protocol Field MUST have value 3" -}
    Left $ "verifyRRSIGwith: protocol number of DNSKEY is not 3: " ++ show dnskey_protocol
  unless (dnskey_pubalg == rrsig_pubalg) $
    Left $ "verifyRRSIGwith: pubkey algorithm mismatch between DNSKEY and RRSIG: " ++ show dnskey_pubalg ++ " =/= " ++ show rrsig_pubalg
  unless (dnskey_pubalg == RSAMD5 || keyTag dnskey == rrsig_key_tag) $ {- not implement keytag computation for RSAMD5 -}
    Left $ "verifyRRSIGwith: Key Tag mismatch between DNSKEY and RRSIG: " ++ show (keyTag dnskey) ++ " =/= " ++ show rrsig_key_tag
  pubkey <- rrsigIGetKey dnskey_public_key
  sig    <- rrsigIGetSig rrsig_signature
  let str = runSPut (putRRSIGHeader rrsig >> putResourceRecord Canonical rr)
  good <- rrsigIVerify pubkey sig str
  unless good $ Left "verifyRRSIGwith: rejected on verification"

rrsigDicts :: Map PubAlg RRSIGImpl
rrsigDicts =
  Map.fromList
  [ (RSASHA1         , rsaSHA1)
  , (RSASHA256       , rsaSHA256)
  , (RSASHA512       , rsaSHA512)
  , (ECDSAP256SHA256 , ecdsaP256SHA)
  , (ECDSAP384SHA384 , ecdsaP384SHA)
  , (ED25519         , ed25519)
  , (ED448           , ed448)
  ]

verifyRRSIG :: RD_DNSKEY -> RD_RRSIG -> ResourceRecord -> Either String ()
verifyRRSIG dnskey rrsig rr =
  maybe (Left $ "verifyRRSIG: unsupported algorithm: " ++ show alg) verify $
  Map.lookup alg rrsigDicts
  where
    alg = dnskey_pubalg dnskey
    verify impl = verifyRRSIGwith impl dnskey rrsig rr

---

verifyDSwith :: DSImpl -> Domain -> RD_DNSKEY -> RD_DS -> Either String ()
verifyDSwith DSImpl{..} owner dnskey@RD_DNSKEY{..} RD_DS{..} = do
  unless (ZONE `elem` dnskey_flags) $
    {- https://datatracker.ietf.org/doc/html/rfc4034#section-5.2
       "The DNSKEY RR referred  to in the DS RR MUST be a DNSSEC zone key." -}
    Left   "verifyDSwith: ZONE flag is not set for DNSKEY flags"
  unless (dnskey_pubalg == ds_pubalg) $
    Left $ "verifyDSwith: pubkey algorithm mismatch between DNSKEY and DS: " ++ show dnskey_pubalg ++ " =/= " ++ show ds_pubalg
  let dnskeyBS = runSPut $ putResourceData Canonical dnskey
  unless (dnskey_pubalg == RSAMD5 || keyTagFromBS dnskeyBS == ds_key_tag) $ {- not implement keytag computation for RSAMD5 -}
    Left $ "verifyRRSIGwith: Key Tag mismatch between DNSKEY and DS: " ++ show (keyTagFromBS dnskeyBS) ++ " =/= " ++ show ds_key_tag
  let digest = dsIGetDigest $ runSPut (putDomain Canonical owner) <> dnskeyBS
      ds_digest' = Opaque.toByteString ds_digest
  unless (dsIVerify digest ds_digest') $
    Left "verifyDSwith: rejected on verification"

dsDicts :: Map DigestAlg DSImpl
dsDicts =
  Map.fromList
  [ (SHA1   , DS.sha1)
  , (SHA256 , DS.sha256)
  , (SHA384 , DS.sha384)
  ]

verifyDS :: Domain -> RD_DNSKEY -> RD_DS -> Either String ()
verifyDS owner dnskey ds =
  maybe (Left $ "verifyDS: unsupported algorithm: " ++ show alg) verify $
  Map.lookup alg dsDicts
  where
    alg = ds_hashalg ds
    verify impl = verifyDSwith impl owner dnskey ds
