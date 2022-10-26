{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.SEC.Verify.Types where

-- dnsext-types
import DNS.Types
import DNS.Types.Internal

-- this package
import DNS.SEC.Imports
import DNS.SEC.Time
import DNS.SEC.PubAlg
import DNS.SEC.PubKey
import DNS.SEC.Types (RD_RRSIG(..), RD_DNSKEY(..))

data RRSIGImpl =
  forall pubkey sig .
  RRSIGImpl
  { rrsigIGetKey :: PubKey -> Either String pubkey
  , rrsigIGetSig :: Opaque -> Either String sig
  , rrsigIVerify :: pubkey -> sig -> ByteString -> Either String Bool
  }

putRRSIGHeader :: RD_RRSIG -> SPut
putRRSIGHeader RD_RRSIG{..} =
  mconcat [ put16    $ fromTYPE rrsig_type
          , putPubAlg  rrsig_pubalg
          , put8       rrsig_num_labels
          , putSeconds rrsig_ttl
          , putDnsTime rrsig_expiration
          , putDnsTime rrsig_inception
          , put16      rrsig_key_tag
          , putDomain Canonical rrsig_zone
          ]

verifyRRSIGwith :: RRSIGImpl -> RD_DNSKEY -> RD_RRSIG -> ResourceRecord -> Either String ()
verifyRRSIGwith RRSIGImpl{..} RD_DNSKEY{..} rrsig@RD_RRSIG{..} rr = do
  unless (dnskey_pubalg == rrsig_pubalg) $
    Left $ "verifyRRSIG: pubkey algorithm mismatch between DNSKEY and RRSIG: " ++ show dnskey_pubalg ++ " =/= " ++ show rrsig_pubalg
  {- TODO: check DNSKEY with keytag -}
  pubkey <- rrsigIGetKey dnskey_public_key
  sig    <- rrsigIGetSig rrsig_signature
  let str = runSPut $ putRRSIGHeader rrsig <> putResourceRecord Canonical rr
  good <- rrsigIVerify pubkey sig str
  unless good $ Left "verifyRRSIG: rejected on verification"
