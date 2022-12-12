{-# LANGUAGE OverloadedStrings #-}

module VerifySpec (spec) where

import Test.Hspec

import Control.Monad (unless)
import Data.String (fromString)
import Data.Int
import Data.Word
import Data.ByteString (ByteString)

import Data.ByteArray.Encoding (Base (Base16, Base64), convertFromBase)

import DNS.Types
import qualified DNS.Types.Opaque as Opaque

import DNS.SEC
import DNS.SEC.Verify

spec :: Spec
spec = do
  describe "KeyTag" $ do
    it "RFC5702 section6.1" $ caseKeyTag keyTagRFC5702
  describe "verify DS" $ do
    it "SHA1"   $ caseDS dsSHA1
    it "SHA256" $ caseDS dsSHA256
    it "SHA384" $ caseDS dsSHA384
  describe "verify RRSIG" $ do
    it "RSA/SHA256" $ caseRRSIG rsaSHA256
    it "RSA/SHA512" $ caseRRSIG rsaSHA512
    it "ECDSA/P256" $ caseRRSIG ecdsaP256
    it "ECDSA/P384" $ caseRRSIG ecdsaP384
    it "Ed25519"    $ caseRRSIG ed25519
    it "Ed448"      $ caseRRSIG ed448

-----
-- KeyTag cases

type KeyTag_Case = (ResourceRecord, Word16)

caseKeyTag :: KeyTag_Case -> Expectation
caseKeyTag (dnskeyRR, tag) = either expectationFailure (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  unless (keyTag dnskey == tag) $
    Left $ "caseKeyTag: keytag does not match: " ++ show (keyTag dnskey) ++ " =/= " ++ show tag
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-- example from https://datatracker.ietf.org/doc/html/rfc5702#section-6.1
keyTagRFC5702 :: KeyTag_Case
keyTagRFC5702 = (ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }, 9033)
  where
    key_rd = rd_dnskey' 256 3 8
             " AwEAAcFcGsaxxdgiuuGmCkVI \
             \ my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P \
             \ kxUdp6p/DlUmObdk= "

-----
-- DS cases

type DS_CASE = (ResourceRecord, ResourceRecord)

caseDS :: DS_CASE -> Expectation
caseDS (dnskeyRR, dsRR) = either expectationFailure (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  ds     <- takeRData "DS"     dsRR
  verifyDS (rrname dnskeyRR) dnskey ds
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-- exampe from  https://datatracker.ietf.org/doc/html/rfc4034#section-5.4
dsSHA1 :: DS_CASE
dsSHA1 =
  ( ResourceRecord { rrname = "dskey.example.com.", rrttl = 86400, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "dskey.example.com.", rrttl = 86400, rrclass = classIN, rrtype = DS, rdata = ds_rd }
  )
  where
    key_rd = rd_dnskey' 256 3 5
             " AQOeiiR0GOMYkDshWoSKz9Xz \
             \ fwJr1AYtsmx3TGkJaNXVbfi/ \
             \ 2pHm822aJ5iI9BMzNXxeYCmZ \
             \ DRD99WYwYqUSdjMmmAphXdvx \
             \ egXd/M5+X7OrzKBaMbCVdFLU \
             \ Uh6DhweJBjEVv5f2wwjM9Xzc \
             \ nOf+EPbtG9DMBmADjFDc2w/r \
             \ ljwvFw=="
    ds_rd = rd_ds' 60485 5 1
            " 2BB183AF5F22588179A53B0A \
            \ 98631FAD1A292118 "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.1
dsSHA256 :: DS_CASE
dsSHA256 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DS, rdata = ds_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 13
             " GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb \
             \ krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== "
    ds_rd = rd_ds' 55648 13 2
            " b4c8c1fe2e7477127b27115656ad6256f424625bf5c1 \
            \ e2770ce6d6e37df61d17 "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.2
dsSHA384 :: DS_CASE
dsSHA384 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DS, rdata = ds_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 14
             " xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1 \
             \ w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8 \
             \ /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 "
    ds_rd = rd_ds' 10771 14 4
            " 72d7b62976ce06438e9c0bf319013cf801f09ecc84b8 \
            \ d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94 \
            \ 6df983d6 "

-----
-- RRSIG cases

type RRSIG_CASE = (ResourceRecord, ResourceRecord, ResourceRecord)

caseRRSIG :: RRSIG_CASE -> Expectation
caseRRSIG (dnskeyRR, target, rrsigRR) = either expectationFailure (const $ pure ()) $ do
  dnskey <- takeRData "DNSKEY" dnskeyRR
  rrsig  <- takeRData "RRSIG"  rrsigRR
  verifyRRSIG dnskey rrsig target
  where
    takeRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr

-- example from https://datatracker.ietf.org/doc/html/rfc5702#section-6.1
rsaSHA256 :: RRSIG_CASE
rsaSHA256 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 256 3 8
             " AwEAAcFcGsaxxdgiuuGmCkVI \
             \ my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P \
             \ kxUdp6p/DlUmObdk= "
    sig_rd = rd_rrsig' A 8 3 3600 1893456000 946684800 9033 "example.net."
             " kRCOH6u7l0QGy9qpC9 \
             \ l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa \
             \ cFYK/lPtPiVYP4bwg== "

-- example from https://datatracker.ietf.org/doc/html/rfc5702#section-6.2
rsaSHA512 :: RRSIG_CASE
rsaSHA512 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 256 3 10
             " AwEAAdHoNTOW+et86KuJOWRD \
             \ p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD \
             \ xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g \
             \ pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL "
    sig_rd = rd_rrsig' A 10 3 3600 1893456000 946684800 3740 "example.net."
             " tsb4wnjRUDnB1BUi+t \
             \ 6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa \
             \ eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL \
             \ DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw \
             \ = "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.1
ecdsaP256 :: RRSIG_CASE
ecdsaP256 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 13
             " GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb \
             \ krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA== "
    sig_rd = rd_rrsig' A 13 3 3600 1284026679 1281607479 55648 "example.net."
             " qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA \
             \ yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw== "

-- example from https://datatracker.ietf.org/doc/html/rfc6605#section-6.2
ecdsaP384 :: RRSIG_CASE
ecdsaP384 =
  ( ResourceRecord { rrname = "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }
  , ResourceRecord { rrname = "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 14
             " xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1 \
             \ w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8 \
             \ /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40 "
    sig_rd = rd_rrsig' A 14 3 3600 1284027625 1281608425 10771 "example.net."
             " /L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP \
             \ 95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz \
             \ WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm "

-- example from https://datatracker.ietf.org/doc/html/rfc8080#section-6.1
ed25519 :: RRSIG_CASE
ed25519 =
  ( ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd_mx 10 "mail.example.com." }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 15
             " l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4= "
    sig_rd = rd_rrsig' MX 15 3 3600 1440021600 1438207200 3613 "example.com."
             " Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkj \
             \ H5GaMWeG96GUVZu6ECKOQmemHDg== "

-- example from https://datatracker.ietf.org/doc/html/rfc8080#section-6.2
ed448 :: RRSIG_CASE
ed448 =
  ( ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd_mx 10 "mail.example.com." }
  , ResourceRecord { rrname = "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 16
             " 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx \
             \ 1FYYUcJKm1MDpJtIA "
    sig_rd = rd_rrsig' MX 16 3 3600 1440021600 1438207200 9713 "example.com."
             " Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3 \
             \ 9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0 \
             \ SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA "

-----
-- helpers

rd_dnskey' :: Word16 -> Word8 -> Word8 -> String -> RData
rd_dnskey' kflags proto walg pubkey = rd_dnskey (toDNSKEYflags kflags) proto alg $ toPubKey alg $ opaqueFromB64 pubkey
  where
    alg = toPubAlg walg

rd_ds' :: Word16 -> Word8 -> Word8 -> String -> RData
rd_ds' keytag pubalg digalg digest = rd_ds keytag (toPubAlg pubalg) (toDigestAlg digalg) (opaqueFromB16Hex digest)

rd_rrsig' :: TYPE -> Word8 -> Word8 -> TTL -> Int64 -> Int64 -> Word16 -> String -> String -> RData
rd_rrsig' typ alg a b c d e dom = rd_rrsig typ (toPubAlg alg) a b c d e (fromString dom) . opaqueFromB64

opaqueFromB16Hex :: String -> Opaque
opaqueFromB16Hex =
  either (error "opaqueFromB16Hex: fail to decode hex") Opaque.fromByteString .
  convertFromBase Base16 . (fromString :: String -> ByteString) . filter (/= ' ')

opaqueFromB64 :: String -> Opaque
opaqueFromB64 =
  either (error "opaqueFromB64: fail to decode base64") Opaque.fromByteString .
  convertFromBase Base64 . (fromString :: String -> ByteString) . filter (/= ' ')
