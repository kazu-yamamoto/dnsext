{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TransformListComp #-}

module RoundTripSpec (spec) where

import Control.Monad (replicateM)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import Data.Either
import qualified Data.IP
import Data.IP (Addr, IP(..), IPv4, IPv6, toIPv4, toIPv6, makeAddrRange)
import Data.Word
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck (Gen, arbitrary, elements, forAll, frequency, listOf, oneof)

import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode

spec :: Spec
spec = do
    prop "IPv4" . forAll genIPv4 $ \ ip4 -> do
        let str = show ip4
        read str `shouldBe` ip4
        show (read str :: IPv4) `shouldBe` str

    prop "IPv6" . forAll genIPv6 $ \ ip6 -> do
        let str = show ip6
        read str `shouldBe` ip6
        show (read str :: IPv6) `shouldBe` str

    prop "TYPE" . forAll genTYPE $ \ t ->
        toTYPE (fromTYPE t) `shouldBe` t

    prop "Domain" . forAll genDomain $ \ dom -> do
        let bs = encodeDomain dom
        decodeDomain bs `shouldBe` Right dom
        fmap encodeDomain (decodeDomain bs) `shouldBe` Right bs

    prop "Mailbox" . forAll genMailbox $ \ dom -> do
        let bs = encodeMailbox dom
        decodeMailbox bs `shouldBe` Right dom
        fmap encodeMailbox (decodeMailbox bs) `shouldBe` Right bs

    prop "DNSFlags" . forAll (genDNSFlags 0x0f) $ \ flgs -> do
        let bs = encodeDNSFlags flgs
        decodeDNSFlags bs `shouldBe` Right flgs
        fmap encodeDNSFlags (decodeDNSFlags bs) `shouldBe` Right bs

    prop "ResourceRecord" . forAll genResourceRecord $ \ rr -> do
        let bs = encodeResourceRecord rr
        decodeResourceRecord bs `shouldBe` Right rr
        fmap encodeResourceRecord (decodeResourceRecord bs) `shouldBe` Right bs

    prop "DNSHeader" . forAll (genDNSHeader 0x0f) $ \ hdr ->
        decodeDNSHeader (encodeDNSHeader hdr) `shouldBe` Right hdr

    prop "DNSMessage" . forAll genDNSMessage $ \ msg ->
        decode (encode msg) `shouldBe` Right msg

    prop "EDNS" . forAll genEDNSHeader $ \(edns, hdr) -> do
        let eh = EDNSheader edns
            m = fromRight (error "prop EDNS") $ decode $ encode $ DNSMessage hdr eh [] [] [] []
        ednsHeader m `shouldBe` eh

----------------------------------------------------------------

genDNSMessage :: Gen DNSMessage
genDNSMessage =
    DNSMessage <$> genDNSHeader 0x0f <*> makeEDNS <*> listOf genQuestion
               <*> listOf genResourceRecord  <*> listOf genResourceRecord
               <*> listOf genResourceRecord
  where
    makeEDNS :: Gen EDNSheader
    makeEDNS = genBool >>= \t ->
        if t then EDNSheader <$> genEDNS
             else pure NoEDNS


genQuestion :: Gen Question
genQuestion = Question <$> genDomain <*> genTYPE <*> pure classIN

genTYPE :: Gen TYPE
genTYPE = frequency
    [ (20, elements
            [ A, AAAA, NS, TXT, MX, CNAME, SOA, PTR, SRV, DNAME, OPT, TLSA ])
    , (1, toTYPE <$> genWord16)
    ]

genResourceRecord :: Gen ResourceRecord
genResourceRecord = frequency
    [ (8, genRR)
    ]
  where
    genRR = do
      dom <- genDomain
      t <- elements [A, AAAA, NS, TXT, MX, CNAME, SOA, PTR, SRV, DNAME, TLSA]
      ResourceRecord dom t classIN <$> genSeconds <*> mkRData dom t

mkRData :: Domain -> TYPE -> Gen RData
mkRData dom typ =
    case typ of
        A     -> rd_a    <$> genIPv4
        AAAA  -> rd_aaaa <$> genIPv6
        NS    -> pure $ rd_ns dom
        TXT   -> rd_txt  <$> genTextString
        MX    -> rd_mx   <$> genWord16 <*> genDomain
        CNAME -> pure $ rd_cname dom
        SOA   -> rd_soa dom <$> genMailbox <*> genWord32 <*> genSeconds <*> genSeconds <*> genSeconds <*> genSeconds
        PTR   -> rd_ptr  <$> genDomain
        SRV   -> rd_srv  <$> genWord16 <*> genWord16 <*> genWord16 <*> genDomain
        DNAME -> rd_dname <$> genDomain
        TLSA  -> rd_tlsa <$> genWord8 <*> genWord8 <*> genWord8 <*> genOpaque

        _ -> pure . rd_txt $ byteStringToOpaque ("Unhandled type " <> C8.pack (show typ))
  where
    genTextString = do
        len <- elements [0, 1, 63, 255, 256, 511, 512, 1023, 1024]
        shortByteStringToOpaque . Short.pack <$> replicateM len genWord8

genIPv4 :: Gen IPv4
genIPv4 = toIPv4 <$> replicateM 4 (fromIntegral <$> genWord8)

genIPv6 :: Gen IPv6
genIPv6 = toIPv6 <$> replicateM 8 (fromIntegral <$> genWord16)

genOpaque :: Gen Opaque
genOpaque = byteStringToOpaque <$> elements [ "", "a", "a.b", "abc", "a.b.c", "a\\.b.c", "\\001.a.b", "\\$.a.b" ]

genDomain :: Gen Domain
genDomain = ciName . (<> ".") <$>  genDomainString
  where
    genDomainString :: Gen String
    genDomainString = elements
        ["", "a", "a.b", "abc", "a.b.c", "a\\.b.c", "\\001.a.b", "\\$.a.b"]

genMailbox :: Gen Mailbox
genMailbox = ciName . (<> ".") <$> genMboxString
  where
    genMboxString :: Gen String
    genMboxString = elements
        ["", "a", "a@b", "abc", "a@b.c", "first.last@example.org"]

genDNSHeader :: Word16 -> Gen DNSHeader
genDNSHeader maxrc = DNSHeader <$> genWord16 <*> genDNSFlags maxrc

genDNSFlags :: Word16 -> Gen DNSFlags
genDNSFlags maxrc =
  DNSFlags <$> genQorR <*> genOPCODE <*> genBool        <*> genBool
           <*> genBool <*> genBool   <*> genRCODE maxrc <*> genBool <*> genBool

genWord16 :: Gen Word16
genWord16 = arbitrary

genWord32 :: Gen Word32
genWord32 = arbitrary

genSeconds :: Gen Seconds
genSeconds = Seconds <$> genWord32

genWord8 :: Gen Word8
genWord8 = arbitrary

genBool :: Gen Bool
genBool = elements [True, False]

genQorR :: Gen QorR
genQorR = elements [minBound .. maxBound]

genOPCODE :: Gen OPCODE
genOPCODE  = elements [OP_STD, OP_INV, OP_SSR, OP_NOTIFY, OP_UPDATE]

genRCODE :: Word16 -> Gen RCODE
genRCODE maxrc = elements $ map toRCODE [0..maxrc]

genEDNS :: Gen EDNS
genEDNS = do
    vers <- genWord8
    ok <- genBool
    od <- genOData
    us <- elements [minUdpSize..maxUdpSize]
    return $ defaultEDNS {
        ednsVersion  = vers
      , ednsUdpSize  = us
      , ednsDnssecOk = ok
      , ednsOptions  = [od]
      }

genOData :: Gen OData
genOData = oneof
    [ genOD_Unknown
    , genOD_ECS
    ]
  where
    -- | Choose from the range reserved for local use
    -- https://tools.ietf.org/html/rfc6891#section-9
    genOD_Unknown = od_unknown <$> elements [65001, 65534] <*> genOpaque

    -- | Only valid ECS prefixes round-trip, make sure the prefix is
    -- is consistent with the mask.
    genOD_ECS = do
        usev4 <- genBool
        if usev4
        then genFuzzed genIPv4 IPv4 Data.IP.fromIPv4  1 32
        else genFuzzed genIPv6 IPv6 Data.IP.fromIPv6b 2 128
      where
        genFuzzed :: Addr a
                  => Gen a
                  -> (a -> IP)
                  -> (a -> [Int])
                  -> Word16
                  -> Word8
                  -> Gen OData
        genFuzzed gen toIP toBytes fam alen = do
            ip <- gen
            bits1 <- elements [1 .. alen]
            bits2 <- elements [0 .. alen]
            fuzzSrcBits <- genBool
            fuzzScpBits <- genBool
            srcBits <- if not fuzzSrcBits
                       then pure bits1
                       else flip mod alen. (+) bits1 <$> elements [1..alen-1]
            scpBits <- if not fuzzScpBits
                       then pure bits2
                       else elements [alen+1 .. 0xFF]
            let addr  = Data.IP.addr. makeAddrRange ip $ fromIntegral bits1
                bytes = map fromIntegral $ toBytes addr
                len   = (fromIntegral bits1 + 7) `div` 8
                less  = take (len - 1) bytes
                more  = less ++ [0xFF]
            if srcBits == bits1
            then if scpBits == bits2
                 then pure $ od_clientSubnet bits1 scpBits $ toIP addr
                 else pure $ od_ecsGeneric fam bits1 scpBits $ byteStringToOpaque $ BS.pack bytes
            else if srcBits < bits1
                 then pure $ od_ecsGeneric fam srcBits scpBits $ byteStringToOpaque $ BS.pack more
                 else pure $ od_ecsGeneric fam srcBits scpBits $ byteStringToOpaque $ BS.pack less

genEDNSHeader :: Gen (EDNS, DNSHeader)
genEDNSHeader = do
    edns <- genEDNS
    hdr <- genDNSHeader 0xF00
    return (edns, hdr)
