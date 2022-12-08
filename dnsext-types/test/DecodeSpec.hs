{-# LANGUAGE OverloadedStrings #-}

module DecodeSpec (spec) where

import qualified Data.ByteString as BS
import Data.ByteString.Internal (ByteString(..), unsafeCreate)
import Data.Word8
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (peek, poke, peekByteOff)
import Test.Hspec

import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode

----------------------------------------------------------------

test_doublePointer :: ByteString
test_doublePointer = "f7eb8500000100010007000404736563330561706e696303636f6d0000010001c00c0001000100001c200004ca0c1c8cc0110002000100001c20000f036e73310561706e6963036e657400c0300002000100001c200006036e7333c040c0300002000100001c200006036e7334c040c0300002000100001c20001004736563310561706e696303636f6d00c0300002000100001c20001704736563310761757468646e730472697065036e657400c0300002000100001c20001004736563320561706e696303636f6d00c0300002000100001c2000070473656333c0bfc07b0001000100001c200004ca0c1d3bc07b001c000100001c20001020010dc02001000a4608000000000059c0ba0001000100001c200004ca0c1d3cc0d6001c000100001c20001020010dc0000100004777000000000140"
-- DNSMessage {header = DNSHeader {identifier = 63467, flags = DNSFlags {qOrR = QR_Response, opcode = OP_STD, authAnswer = True, trunCation = False, recDesired = True, recAvailable = False, rcode = NoErr, authenData = False}}, question = [Question {qname = "sec3.apnic.com.", qtype = A}], answer = [ResourceRecord {rrname = "sec3.apnic.com.", rrtype = A, rrttl = 7200, rdata = 202.12.28.140}], authority = [ResourceRecord {rrname = "apnic.com.", rrtype = NS, rrttl = 7200, rdata = ns1.apnic.net.},ResourceRecord {rrname = "apnic.com.", rrtype = NS, rrttl = 7200, rdata = ns3.apnic.net.},ResourceRecord {rrname = "apnic.com.", rrtype = NS, rrttl = 7200, rdata = ns4.apnic.net.},ResourceRecord {rrname = "apnic.com.", rrtype = NS, rrttl = 7200, rdata = sec1.apnic.com.},ResourceRecord {rrname = "apnic.com.", rrtype = NS, rrttl = 7200, rdata = sec1.authdns.ripe.net.},ResourceRecord {rrname = "apnic.com.", rrtype = NS, rrttl = 7200, rdata = sec2.apnic.com.},ResourceRecord {rrname = "apnic.com.", rrtype = NS, rrttl = 7200, rdata = sec3.apnic.com.}], additional = [ResourceRecord {rrname = "sec1.apnic.com.", rrtype = A, rrttl = 7200, rdata = 202.12.29.59},ResourceRecord {rrname = "sec1.apnic.com.", rrtype = AAAA, rrttl = 7200, rdata = 2001:dc0:2001:a:4608::59},ResourceRecord {rrname = "sec2.apnic.com.", rrtype = A, rrttl = 7200, rdata = 202.12.29.60},ResourceRecord {rrname = "sec3.apnic.com.", rrtype = AAAA, rrttl = 7200, rdata = 2001:dc0:1:0:4777::140}]})

test_txt :: ByteString
test_txt = "463181800001000100000000076e69636f6c6173046b766462076e647072696d6102696f0000100001c00c0010000100000e10000d0c6e69636f6c61732e6b766462"
-- DNSMessage {header = DNSHeader {identifier = 17969, flags = DNSFlags {qOrR = QR_Response, opcode = OP_STD, authAnswer = False, trunCation = False, recDesired = True, recAvailable = True, rcode = NoErr, authenData = False}}
--              , question = [Question {qname = "nicolas.kvdb.ndprima.io.", qtype = TXT}]
--              , answer = [ResourceRecord {rrname = "nicolas.kvdb.ndprima.io.", rrtype = TXT, rrttl = 3600, rdata = nicolas.kvdb}]
--              , authority = []
--              , additional = []})

test_dname :: ByteString
test_dname = "b3c0818000010005000200010377777706376b616e616c02636f02696c0000010001c0100027000100000003000c0769737261656c3702727500c00c0005000100000003000603777777c02ec046000500010000255b0002c02ec02e000100010000003d000451daf938c02e000100010000003d0004c33ce84ac02e000200010005412b000c036e7332026137036f726700c02e000200010005412b0006036e7331c08a0000291000000000000000"
-- DNSMessage {header = DNSHeader {identifier = 46016, flags = DNSFlags {qOrR = QR_Response, opcode = OP_STD, authAnswer = False, trunCation = False, recDesired = True, recAvailable = True, rcode = NoErr, authenData = False}}, question = [Question {qname = "www.7kanal.co.il.", qtype = A}], answer = [ResourceRecord {rrname = "7kanal.co.il.", rrtype = DNAME, rrttl = 3, rdata = israel7.ru.},ResourceRecord {rrname = "www.7kanal.co.il.", rrtype = CNAME, rrttl = 3, rdata = www.israel7.ru.},ResourceRecord {rrname = "www.israel7.ru.", rrtype = CNAME, rrttl = 9563, rdata = israel7.ru.},ResourceRecord {rrname = "israel7.ru.", rrtype = A, rrttl = 61, rdata = 81.218.249.56},ResourceRecord {rrname = "israel7.ru.", rrtype = A, rrttl = 61, rdata = 195.60.232.74}], authority = [ResourceRecord {rrname = "israel7.ru.", rrtype = NS, rrttl = 344363, rdata = ns2.a7.org.},ResourceRecord {rrname = "israel7.ru.", rrtype = NS, rrttl = 344363, rdata = ns1.a7.org.}], additional = [OptRecord {orudpsize = 4096, ordnssecok = False, orversion = 0, rdata = []}]})

test_mx :: ByteString
test_mx = "f03681800001000100000001036d6577036f726700000f0001c00c000f000100000df10009000a046d61696cc00c0000291000000000000000"
-- DNSMessage {header = DNSHeader {identifier = 61494, flags = DNSFlags {qOrR = QR_Response, opcode = OP_STD, authAnswer = False, trunCation = False, recDesired = True, recAvailable = True, rcode = NoErr, authenData = False}}
--              , question = [Question {qname = "mew.org.", qtype = MX}]
--              , answer = [ResourceRecord {rrname = "mew.org.", rrtype = MX, rrttl = 3569, rdata = 10 mail.mew.org.}]
--              , authority = []
--              , additional = [OptRecord {orudpsize = 4096, ordnssecok = False, orversion = 0, rdata = []}]})

-- Message with question domain == SOA rname, testing correct decoding of
-- of the rname to presentation form when it encoded in compressed form
-- as a pointer to the question domain.
test_soa :: DNSMessage
test_soa =
    let q = [Question "hostmaster.example.com." A classIN]
        soard = rd_soa "ns1.example.com." "hostmaster@example.com." 0 0 0 0 0
        soarr = ResourceRecord "example.com." SOA 1 3600 soard
     in defaultResponse { question = q
                        , authority = [soarr] }

-- Expected compressed encoding of the 'test_soa' message
test_soa_bytes :: ByteString
test_soa_bytes = "0000858000010000000100000a686f73746d6173746572076578616d706c6503636f6d0000010001c0170006000100000e10001c036e7331c017c00c0000000000000000000000000000000000000000"

----------------------------------------------------------------

spec :: Spec
spec = do
    describe "decode" $ do
        it "decodes double pointers correctly" $
            tripleDecodeTest test_doublePointer
        it "decodes dname" $
            tripleDecodeTest test_dname
        it "decodes txt" $
            tripleDecodeTest test_txt
        it "decodes mx" $
            tripleDecodeTest test_mx
        it "detect excess" $
            case decode (encode defaultQuery <> "\0") of
                Left (DecodeError {}) -> True
                _ -> error "Excess input not detected"
        it "detect truncation" $
            case decode (BS.init $ encode defaultQuery) of
                Left (DecodeError {}) -> True
                _ -> error "Excess input not detected"
        it "soa mailbox presentation form" $
            case encode test_soa of
                enc | enc /= fromHexString test_soa_bytes
                    -> error "Unexpected test_soa encoding"
                    | otherwise -> case decode enc of
                        Left err  -> error $ "Error decoding test_soa: " ++ show err
                        Right m | m /= test_soa
                                  -> error $ "Wrong decode of test_soa: " ++ show m
                                | otherwise -> True

tripleDecodeTest :: ByteString -> IO ()
tripleDecodeTest hexbs =
    ecase (decode $ fromHexString hexbs) fail' $ \ x1 ->
        ecase (decode $ encode x1) fail' $ \ x2 ->
            ecase (decode $ encode x2) fail' $ \ x3 ->
                x3 `shouldBe` x2
  where
    fail' (DecodeError err) = fail err
    fail' _                 = error "fail'"

ecase :: Either a b -> (a -> c) -> (b -> c) -> c
ecase (Left  a) f _ = f a
ecase (Right b) _ g = g b

----------------------------------------------------------------

fromHexString :: ByteString -> ByteString
fromHexString (PS fptr off len) = unsafeCreate size $ \dst ->
    withForeignPtr fptr $ \src -> go (src `plusPtr` off) dst 0
  where
    size = len `div` 2
    go from to bytes
      | bytes == size = return ()
      | otherwise    = do
          w1 <- peek from
          w2 <- peekByteOff from 1
          let w = hex2w (w1,w2)
          poke to w
          go (from `plusPtr` 2) (to `plusPtr` 1) (bytes + 1)

hex2w :: (Word8, Word8) -> Word8
hex2w (w1,w2) = h2w w1 * 16 + h2w w2

h2w :: Word8 -> Word8
h2w w
  | isDigit w = w - _0
  | otherwise = w - _a + 10
