module DNS.SEC.Verify.Verify where

import Data.Map (Map)
import qualified Data.Map as Map

-- dnsext-types
import DNS.Types

-- this package
import DNS.SEC.PubAlg
import DNS.SEC.HashAlg
import DNS.SEC.Types (RD_RRSIG(..), RD_DNSKEY(..), RD_DS (..))

import DNS.SEC.Verify.Types (RRSIGImpl, verifyRRSIGwith, DSImpl, verifyDSwith)
import DNS.SEC.Verify.RSA (rsaSHA1, rsaSHA256, rsaSHA512)
import DNS.SEC.Verify.ECDSA (ecdsaP256SHA, ecdsaP384SHA)
import DNS.SEC.Verify.EdDSA (ed25519, ed448)
import qualified DNS.SEC.Verify.SHA as DS


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
