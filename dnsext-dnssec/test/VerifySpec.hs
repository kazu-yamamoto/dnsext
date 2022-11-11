module VerifySpec (spec) where

import Test.Hspec

import Data.String (fromString)
import Data.Int
import Data.Word
import Data.ByteString (ByteString)

import Data.ByteArray.Encoding (Base (Base64), convertFromBase)

import DNS.Types
import qualified DNS.Types.Opaque as Opaque

import DNS.SEC
import DNS.SEC.Verify

spec :: Spec
spec = do
  describe "verify RRSIG" $ do
    it "RSA/SHA256" $ checkVerify rsaSHA256
    it "RSA/SHA512" $ checkVerify rsaSHA512
    it "ECDSA/P256" $ checkVerify ecdsaP256
    it "ECDSA/P384" $ checkVerify ecdsaP384
    it "Ed25519"    $ checkVerify ed25519
    it "Ed448"      $ checkVerify ed448

type RRSIG_CASE = (ResourceRecord, ResourceRecord, ResourceRecord)

checkVerify :: RRSIG_CASE -> Expectation
checkVerify (dnskeyRR, target, rrsigRR) = either expectationFailure (const $ pure ()) $ do
  let getRData name rr = maybe (Left $ "not " ++ name ++ ": " ++ show rd) Right $ fromRData rd  where rd = rdata rr
  dnskey <- getRData "DNSKEY" dnskeyRR
  rrsig  <- getRData "RRSIG"  rrsigRR
  verifyRRSIG dnskey rrsig target

-- example from https://datatracker.ietf.org/doc/html/rfc5702#section-6.1
rsaSHA256 :: RRSIG_CASE
rsaSHA256 =
  ( ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
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
  ( ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.91" }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
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
  ( ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
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
  ( ResourceRecord { rrname = fromString "example.net.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = A, rdata = rd_a $ read "192.0.2.1" }
  , ResourceRecord { rrname = fromString "www.example.net.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
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
  ( ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd_mx 10 (fromString "mail.example.com.") }
  , ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
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
  ( ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = DNSKEY, rdata = key_rd }
  , ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = MX, rdata = rd_mx 10 (fromString "mail.example.com.") }
  , ResourceRecord { rrname = fromString "example.com.", rrttl = 3600, rrclass = classIN, rrtype = RRSIG, rdata = sig_rd }
  )
  where
    key_rd = rd_dnskey' 257 3 16
             " 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx \
             \ 1FYYUcJKm1MDpJtIA "
    sig_rd = rd_rrsig' MX 16 3 3600 1440021600 1438207200 9713 "example.com."
             " Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3 \
             \ 9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0 \
             \ SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA "

opaqueFromB64' :: String -> Opaque
opaqueFromB64' =
  either (error "opaqueFromB64': fail to decode base64") Opaque.fromByteString .
  convertFromBase Base64 . (fromString :: String -> ByteString) . filter (/= ' ')

rd_dnskey' :: Word16 -> Word8 -> Word8 -> String -> RData
rd_dnskey' kflags proto walg pubkey = rd_dnskey (toDNSKEYflags kflags) proto alg $ toPubKey alg $ opaqueFromB64' pubkey
  where
    alg = toPubAlg walg

rd_rrsig' :: TYPE -> Word8 -> Word8 -> TTL -> Int64 -> Int64 -> Word16 -> String -> String -> RData
rd_rrsig' typ alg a b c d e dom = rd_rrsig typ (toPubAlg alg) a b c d e (fromString dom) . opaqueFromB64'
