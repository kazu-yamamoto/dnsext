{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Types.Message where

import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Lazy.Char8 as LC8

import DNS.StateBinary
import DNS.Types.Dict
import DNS.Types.Domain
import DNS.Types.EDNS
import DNS.Types.Imports
import DNS.Types.RData
import DNS.Types.Seconds
import DNS.Types.Type

-- $setup
-- >>> import DNS.Types

----------------------------------------------------------------

-- | Data type representing the optional EDNS pseudo-header of a 'DNSMessage'
-- When a single well-formed @OPT@ 'ResourceRecord' was present in the
-- message's additional section, it is decoded to an 'EDNS' record and and
-- stored in the message 'ednsHeader' field.  The corresponding @OPT RR@ is
-- then removed from the additional section.
--
-- When the constructor is 'NoEDNS', no @EDNS OPT@ record was present in the
-- message additional section.  When 'InvalidEDNS', the message holds either a
-- malformed OPT record or more than one OPT record, which can still be found
-- in (have not been removed from) the message additional section.
--
-- The EDNS OPT record augments the message error status with an 8-bit field
-- that forms 12-bit extended RCODE when combined with the 4-bit RCODE from the
-- unextended DNS header.  In EDNS messages it is essential to not use just the
-- bare 4-bit 'RCODE' from the original DNS header.  Therefore, in order to
-- avoid potential misinterpretation of the response 'RCODE', when the OPT
-- record is decoded, the upper eight bits of the error status are
-- automatically combined with the 'rcode' of the message header, so that there
-- is only one place in which to find the full 12-bit result.  Therefore, the
-- decoded 'EDNS' pseudo-header, does not hold any error status bits.
--
-- The reverse process occurs when encoding messages.  The low four bits of the
-- message header 'rcode' are encoded into the wire-form DNS header, while the
-- upper eight bits are encoded as part of the OPT record.  In DNS responses with
-- an 'rcode' larger than 15, EDNS extensions SHOULD be enabled by providing a
-- value for 'ednsHeader' with a constructor of 'EDNSheader'.  If EDNS is not
-- enabled in such a message, in order to avoid truncation of 'RCODE' values
-- that don't fit in the non-extended DNS header, the encoded wire-form 'RCODE'
-- is set to 'FormatErr'.
--
-- When encoding messages for transmission, the 'ednsHeader' is used to
-- generate the additional OPT record.  Do not add explicit @OPT@ records
-- to the aditional section, configure EDNS via the 'EDNSheader' instead.
--
data EDNSheader = EDNSheader EDNS -- ^ A valid EDNS message
                | NoEDNS          -- ^ A valid non-EDNS message
                | InvalidEDNS     -- ^ Multiple or bad additional @OPT@ RRs
    deriving (Eq, Show)


-- | Return the second argument for EDNS messages, otherwise the third.
ifEDNS :: EDNSheader -- ^ EDNS pseudo-header
       -> a          -- ^ Value to return for EDNS messages
       -> a          -- ^ Value to return for non-EDNS messages
       -> a
ifEDNS (EDNSheader _) a _ = a
ifEDNS             _  _ b = b
{-# INLINE ifEDNS #-}


-- | Return the output of a function applied to the EDNS pseudo-header if EDNS
--   is enabled, otherwise return a default value.
mapEDNS :: EDNSheader  -- ^ EDNS pseudo-header
        -> (EDNS -> a) -- ^ Function to apply to 'EDNS' value
        -> a           -- ^ Default result for non-EDNS messages
        -> a
mapEDNS (EDNSheader eh) f _ = f eh
mapEDNS               _ _ a = a
{-# INLINE mapEDNS #-}

----------------------------------------------------------------

-- | DNS message format for queries and replies.
--
data DNSMessage = DNSMessage {
    header     :: DNSHeader         -- ^ Header with extended 'RCODE'
  , ednsHeader :: EDNSheader        -- ^ EDNS pseudo-header
  , question   :: [Question]        -- ^ The question for the name server
  , answer     :: Answers           -- ^ RRs answering the question
  , authority  :: AuthorityRecords  -- ^ RRs pointing toward an authority
  , additional :: AdditionalRecords -- ^ RRs holding additional information
  } deriving (Eq, Show)

-- | An identifier assigned by the program that
--   generates any kind of query.
type Identifier = Word16

putDNSMessage :: DNSMessage -> SPut
putDNSMessage msg = putHeader hd
                    <> putNums
                    <> mconcat (map putQuestion qs)
                    <> mconcat (map putRR an)
                    <> mconcat (map putRR au)
                    <> mconcat (map putRR ad)
  where
    putNums = mconcat $ fmap putInt16 [ length qs
                                      , length an
                                      , length au
                                      , length ad
                                      ]
    putRR = putResourceRecord Compression
    hm = header msg
    fl = flags hm
    eh = ednsHeader msg
    qs = question msg
    an = answer msg
    au = authority msg
    hd = ifEDNS eh hm $ hm { flags = fl { rcode = rc } }
    rc = ifEDNS eh <$> id <*> nonEDNSrcode $ rcode fl
      where
        nonEDNSrcode code | fromRCODE code < 16 = code
                          | otherwise           = FormatErr
    ad = prependOpt $ additional msg
      where
        prependOpt ads = mapEDNS eh (fromEDNS ads $ fromRCODE rc) ads
          where
            fromEDNS :: AdditionalRecords -> Word16 -> EDNS -> AdditionalRecords
            fromEDNS rrs rc' edns = ResourceRecord name' type' class' ttl' rdata' : rrs
              where
                name'  = "."
                type'  = OPT
                class' = maxUdpSize `min` (minUdpSize `max` ednsUdpSize edns)
                ttl0'  = fromIntegral (rc' .&. 0xff0) `shiftL` 20
                vers'  = fromIntegral (ednsVersion edns) `shiftL` 16
                ttl'
                  | ednsDnssecOk edns = ttl0' `setBit` 15 .|. vers'
                  | otherwise         = ttl0' .|. vers'
                rdata' = RData $ RD_OPT $ ednsOptions edns

getDNSMessage :: SGet DNSMessage
getDNSMessage = do
    hm <- getHeader
    qdCount <- getInt16
    anCount <- getInt16
    nsCount <- getInt16
    arCount <- getInt16
    queries <- getQuestions qdCount
    answers <- getResourceRecords anCount
    authrrs <- getResourceRecords nsCount
    addnrrs <- getResourceRecords arCount
    let (opts, rest) = partition ((==) OPT. rrtype) addnrrs
        flgs         = flags hm
        rc           = fromRCODE $ rcode flgs
        (eh, erc)    = getEDNS rc opts
        hd           = hm { flags = flgs { rcode = erc } }
    pure $ DNSMessage hd eh queries answers authrrs $ ifEDNS eh rest addnrrs

  where

    -- | Get EDNS pseudo-header and the high eight bits of the extended RCODE.
    --
    getEDNS :: Word16 -> AdditionalRecords -> (EDNSheader, RCODE)
    getEDNS rc rrs = case rrs of
        [rr] | Just (edns, erc) <- optEDNS rr
               -> (EDNSheader edns, toRCODE erc)
        []     -> (NoEDNS, toRCODE rc)
        _      -> (InvalidEDNS, BadRCODE)

      where

        -- | Extract EDNS information from an OPT RR.
        --
        optEDNS :: ResourceRecord -> Maybe (EDNS, Word16)
        optEDNS (ResourceRecord "." OPT udpsiz ttl' rd) = case fromRData rd of
            Just (RD_OPT opts) ->
                let hrc      = fromIntegral rc .&. 0x0f
                    erc      = shiftR (ttl' .&. 0xff000000) 20 .|. hrc
                    secok    = ttl' `testBit` 15
                    vers     = fromIntegral $ shiftR (ttl' .&. 0x00ff0000) 16
                in Just (EDNS vers udpsiz secok opts, fromIntegral erc)
            _ -> Nothing
        optEDNS _ = Nothing

----------------------------------------------------------------

-- | A 'DNSMessage' template for queries with default settings for
-- the message 'DNSHeader' and 'EDNSheader'.  This is the initial
-- query message state, before customization via 'QueryControls'.
--
defaultQuery :: DNSMessage
defaultQuery = DNSMessage {
    header = DNSHeader {
       identifier = 0
     , flags = defaultDNSFlags
     }
  , ednsHeader = EDNSheader defaultEDNS
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

-- | Construct a complete query 'DNSMessage', by combining the 'defaultQuery'
-- template with the specified 'Identifier', and 'Question'.
--
makeQuery :: Identifier        -- ^ Crypto random request id
          -> Question          -- ^ Question name and type
          -> DNSMessage
makeQuery idt q = defaultQuery {
      header = (header defaultQuery) { identifier = idt }
    , question = [q]
    }

-- | Default response.  When responding to EDNS queries, the response must
-- either be an EDNS response, or else FormatErr must be returned.  The default
-- response message has EDNS disabled ('ednsHeader' set to 'NoEDNS'), it should
-- be updated as appropriate.
--
-- Do not explicitly add OPT RRs to the additional section, instead let the
-- encoder compute and add the OPT record based on the EDNS pseudo-header.
--
-- The 'RCODE' in the 'DNSHeader' should be set to the appropriate 12-bit
-- extended value, which will be split between the primary header and EDNS OPT
-- record during message encoding (low 4 bits in DNS header, high 8 bits in
-- EDNS OPT record).  See 'EDNSheader' for more details.
--
defaultResponse :: DNSMessage
defaultResponse = DNSMessage {
    header = DNSHeader {
       identifier = 0
     , flags = defaultDNSFlags {
              qOrR = QR_Response
            , authAnswer = True
            , recAvailable = True
            , authenData = False
       }
     }
  , ednsHeader = NoEDNS
  , question   = []
  , answer     = []
  , authority  = []
  , additional = []
  }

-- | Construct a response 'DNSMessage'.
makeResponse :: Identifier
             -> Question
             -> Answers
             -> DNSMessage
makeResponse idt q as = defaultResponse {
      header = header' { identifier = idt }
    , question = [q]
    , answer   = as
    }
  where
    header' = header defaultResponse

----------------------------------------------------------------

-- | Raw data format for the header of DNS Query and Response.
data DNSHeader = DNSHeader {
    identifier :: Identifier -- ^ Query or reply identifier.
  , flags      :: DNSFlags   -- ^ Flags, OPCODE, and RCODE
  } deriving (Eq, Show)

-- | Raw data format for the flags of DNS Query and Response.
data DNSFlags = DNSFlags {
    qOrR         :: QorR   -- ^ Query or response.
  , opcode       :: OPCODE -- ^ Kind of query.
  , authAnswer   :: Bool   -- ^ AA (Authoritative Answer) bit - this bit is valid in responses,
                            -- and specifies that the responding name server is an
                            -- authority for the domain name in question section.
  , trunCation   :: Bool   -- ^ TC (Truncated Response) bit - specifies that this message was truncated
                            -- due to length greater than that permitted on the
                            -- transmission channel.
  , recDesired   :: Bool   -- ^ RD (Recursion Desired) bit - this bit may be set in a query and
                            -- is copied into the response.  If RD is set, it directs
                            -- the name server to pursue the query recursively.
                            -- Recursive query support is optional.
  , recAvailable :: Bool   -- ^ RA (Recursion Available) bit - this be is set or cleared in a
                            -- response, and denotes whether recursive query support is
                            -- available in the name server.

  , rcode        :: RCODE  -- ^ The full 12-bit extended RCODE when EDNS is in use.
                            -- Should always be zero in well-formed requests.
                            -- When decoding replies, the high eight bits from
                            -- any EDNS response are combined with the 4-bit
                            -- RCODE from the DNS header.  When encoding
                            -- replies, if no EDNS OPT record is provided, RCODE
                            -- values > 15 are mapped to 'FormatErr'.
  , authenData   :: Bool   -- ^ AD (Authenticated Data) bit - (RFC4035, Section 3.2.3).
  , chkDisable   :: Bool   -- ^ CD (Checking Disabled) bit - (RFC4035, Section 3.2.2).
  } deriving (Eq, Show)

putHeader :: DNSHeader -> SPut
putHeader hdr = putIdentifier (identifier hdr)
             <> putDNSFlags (flags hdr)
  where
    putIdentifier = put16

getHeader :: SGet DNSHeader
getHeader =
    DNSHeader <$> decodeIdentifier <*> getDNSFlags
  where
    decodeIdentifier = get16

----------------------------------------------------------------

-- | Default 'DNSFlags' record suitable for making recursive queries.  By default
-- the RD bit is set, and the AD and CD bits are cleared.
--
defaultDNSFlags :: DNSFlags
defaultDNSFlags = DNSFlags
         { qOrR         = QR_Query
         , opcode       = OP_STD
         , authAnswer   = False
         , trunCation   = False
         , recDesired   = True
         , recAvailable = False
         , authenData   = False
         , chkDisable   = False
         , rcode        = NoErr
         }

putDNSFlags :: DNSFlags -> SPut
putDNSFlags DNSFlags{..} = put16 word
  where
    set :: Word16 -> State Word16 ()
    set byte = modify (.|. byte)

    st :: State Word16 ()
    st = sequence_
              [ set (fromRCODE rcode .&. 0x0f)
              , when chkDisable          $ set (bit 4)
              , when authenData          $ set (bit 5)
              , when recAvailable        $ set (bit 7)
              , when recDesired          $ set (bit 8)
              , when trunCation          $ set (bit 9)
              , when authAnswer          $ set (bit 10)
              , set (fromOPCODE opcode `shiftL` 11)
              , when (qOrR == QR_Response) $ set (bit 15)
              ]

    word = execState st 0

getDNSFlags :: SGet DNSFlags
getDNSFlags = do
    flgs <- get16
    let oc = getOpcode flgs
    return $ DNSFlags (getQorR flgs)
                      oc
                      (getAuthAnswer flgs)
                      (getTrunCation flgs)
                      (getRecDesired flgs)
                      (getRecAvailable flgs)
                      (getRcode flgs)
                      (getAuthenData flgs)
                      (getChkDisable flgs)
  where
    getQorR w = if testBit w 15 then QR_Response else QR_Query
    getOpcode w = toOPCODE (shiftR w 11 .&. 0x0f)
    getAuthAnswer w = testBit w 10
    getTrunCation w = testBit w 9
    getRecDesired w = testBit w 8
    getRecAvailable w = testBit w 7
    getRcode w = toRCODE $ w .&. 0x0f
    getAuthenData w = testBit w 5
    getChkDisable w = testBit w 4

----------------------------------------------------------------

-- | Query or response.
data QorR = QR_Query    -- ^ Query.
          | QR_Response -- ^ Response.
          deriving (Eq, Show, Enum, Bounded)

----------------------------------------------------------------

-- | Kind of query.
newtype OPCODE = OPCODE {
    -- | Convert an 'OPCODE' to its numeric value.
    fromOPCODE :: Word16
  } deriving (Eq)

-- | A standard query.
pattern OP_STD    :: OPCODE
pattern OP_STD     = OPCODE 0
-- | An inverse query (inverse queries are deprecated).
pattern OP_INV    :: OPCODE
pattern OP_INV     = OPCODE 1
-- | A server status request.
pattern OP_SSR    :: OPCODE
pattern OP_SSR     = OPCODE 2
-- OPCODE 3 is not assigned
-- | A zone change notification (RFC1996)
pattern OP_NOTIFY :: OPCODE
pattern OP_NOTIFY  = OPCODE 4
-- | An update request (RFC2136)
pattern OP_UPDATE :: OPCODE
pattern OP_UPDATE = OPCODE 5

-- | Convert a 16-bit DNS OPCODE number to its internal representation
--
toOPCODE :: Word16 -> OPCODE
toOPCODE = OPCODE

instance Show OPCODE where
    show OP_STD     = "OP_STD"
    show OP_INV     = "OP_INV"
    show OP_SSR     = "OP_SSR"
    show OP_NOTIFY  = "OP_NOTIFY"
    show OP_UPDATE  = "OP_UPDATE"
    show (OPCODE n) = "OPCODE " ++ show n

----------------------------------------------------------------

-- | EDNS extended 12-bit response code.  Non-EDNS messages use only the low 4
-- bits.  With EDNS this stores the combined error code from the DNS header and
-- and the EDNS psuedo-header. See 'EDNSheader' for more detail.
newtype RCODE = RCODE {
    -- | Convert an 'RCODE' to its numeric value.
    fromRCODE :: Word16
  } deriving (Eq)

-- | Provide an Enum instance for backwards compatibility
instance Enum RCODE where
    fromEnum = fromIntegral . fromRCODE
    toEnum = RCODE . fromIntegral

-- | No error condition.
pattern NoErr     :: RCODE
pattern NoErr      = RCODE  0
-- | Format error - The name server was
--   unable to interpret the query.
pattern FormatErr :: RCODE
pattern FormatErr  = RCODE  1
-- | Server failure - The name server was
--   unable to process this query due to a
--   problem with the name server.
pattern ServFail  :: RCODE
pattern ServFail   = RCODE  2
-- | Name Error - Meaningful only for
--   responses from an authoritative name
--   server, this code signifies that the
--   domain name referenced in the query does
--   not exist.
pattern NameErr   :: RCODE
pattern NameErr    = RCODE  3
-- | Not Implemented - The name server does
--   not support the requested kind of query.
pattern NotImpl   :: RCODE
pattern NotImpl    = RCODE  4
-- | Refused - The name server refuses to
--   perform the specified operation for
--   policy reasons.  For example, a name
--   server may not wish to provide the
--   information to the particular requester,
--   or a name server may not wish to perform
--   a particular operation (e.g., zone
--   transfer) for particular data.
pattern Refused   :: RCODE
pattern Refused    = RCODE  5
-- | YXDomain - Dynamic update response, a pre-requisite domain that should not
-- exist, does exist.
pattern YXDomain :: RCODE
pattern YXDomain  = RCODE 6
-- | YXRRSet - Dynamic update response, a pre-requisite RRSet that should not
-- exist, does exist.
pattern YXRRSet  :: RCODE
pattern YXRRSet   = RCODE 7
-- | NXRRSet - Dynamic update response, a pre-requisite RRSet that should
-- exist, does not exist.
pattern NXRRSet  :: RCODE
pattern NXRRSet   = RCODE 8
-- | NotAuth - Dynamic update response, the server is not authoritative for the
-- zone named in the Zone Section.
pattern NotAuth  :: RCODE
pattern NotAuth   = RCODE 9
-- | NotZone - Dynamic update response, a name used in the Prerequisite or
-- Update Section is not within the zone denoted by the Zone Section.
pattern NotZone  :: RCODE
pattern NotZone   = RCODE 10
-- | Bad OPT Version (BADVERS, RFC 6891).
pattern BadVers   :: RCODE
pattern BadVers    = RCODE 16
-- | Key not recognized [RFC2845]
pattern BadKey    :: RCODE
pattern BadKey     = RCODE 17
-- | Signature out of time window [RFC2845]
pattern BadTime   :: RCODE
pattern BadTime    = RCODE 18
-- | Bad TKEY Mode [RFC2930]
pattern BadMode   :: RCODE
pattern BadMode    = RCODE 19
-- | Duplicate key name [RFC2930]
pattern BadName   :: RCODE
pattern BadName    = RCODE 20
-- | Algorithm not supported [RFC2930]
pattern BadAlg    :: RCODE
pattern BadAlg     = RCODE 21
-- | Bad Truncation [RFC4635]
pattern BadTrunc  :: RCODE
pattern BadTrunc   = RCODE 22
-- | Bad/missing Server Cookie [RFC7873]
pattern BadCookie :: RCODE
pattern BadCookie  = RCODE 23
-- | Malformed (peer) EDNS message, no RCODE available.  This is not an RCODE
-- that can be sent by a peer.  It lies outside the 12-bit range expressible
-- via EDNS.  The low 12-bits are chosen to coincide with 'FormatErr'.  When
-- an EDNS message is malformed, and we're unable to extract the extended RCODE,
-- the header 'rcode' is set to 'BadRCODE'.
pattern BadRCODE  :: RCODE
pattern BadRCODE   = RCODE 0x1001

-- | Use https://tools.ietf.org/html/rfc2929#section-2.3 names for DNS RCODEs
instance Show RCODE where
    show NoErr     = "NoError"
    show FormatErr = "FormErr"
    show ServFail  = "ServFail"
    show NameErr   = "NXDomain"
    show NotImpl   = "NotImp"
    show Refused   = "Refused"
    show YXDomain  = "YXDomain"
    show YXRRSet   = "YXRRSet"
    show NotAuth   = "NotAuth"
    show NotZone   = "NotZone"
    show BadVers   = "BadVers"
    show BadKey    = "BadKey"
    show BadTime   = "BadTime"
    show BadMode   = "BadMode"
    show BadName   = "BadName"
    show BadAlg    = "BadAlg"
    show BadTrunc  = "BadTrunc"
    show BadCookie = "BadCookie"
    show (RCODE n) = "RCODE " ++ show n

-- | Convert a numeric value to a corresponding 'RCODE'.  The behaviour is
-- undefined for values outside the range @[0 .. 0xFFF]@ since the EDNS
-- extended RCODE is a 12-bit value.  Values in the range @[0xF01 .. 0xFFF]@
-- are reserved for private use.
toRCODE :: Word16 -> RCODE
toRCODE = RCODE

----------------------------------------------------------------

-- | Raw data format for DNS questions.
data Question = Question {
    qname  :: Domain -- ^ A domain name
  , qtype  :: TYPE   -- ^ The type of the query
  , qclass :: CLASS
  } deriving (Eq, Show)

putQuestion :: Question -> SPut
putQuestion Question{..} = putDomain Compression qname
                        <> put16 (fromTYPE qtype)
                        <> putCLASS qclass

----------------------------------------------------------------

-- | Resource record class.
type CLASS = Word16

-- | Resource record class for the Internet.
classIN :: CLASS
classIN = 1

putCLASS :: CLASS -> SPut
putCLASS = put16

getCLASS :: SGet CLASS
getCLASS = get16

-- | Time to live in second.
type TTL = Seconds

-- | Raw data format for resource records.
data ResourceRecord = ResourceRecord {
    rrname  :: Domain -- ^ Name
  , rrtype  :: TYPE   -- ^ Resource record type
  , rrclass :: CLASS  -- ^ Resource record class
  , rrttl   :: TTL    -- ^ Time to live
  , rdata   :: RData  -- ^ Resource data
  } deriving (Eq,Show)

-- | Type alias for resource records in the answer section.
type Answers = [ResourceRecord]

-- | Type alias for resource records in the answer section.
type AuthorityRecords = [ResourceRecord]

-- | Type for resource records in the additional section.
type AdditionalRecords = [ResourceRecord]

putResourceRecord :: CanonicalFlag -> ResourceRecord -> SPut
putResourceRecord cf ResourceRecord{..} = mconcat [
    putDomain cf rrname
  , putTYPE      rrtype
  , putCLASS     rrclass
  , putSeconds   rrttl
  , putResourceRData rdata
  ]
  where
    putResourceRData :: RData -> SPut
    putResourceRData (RData rd) = do
        addBuilderPosition 2 -- "simulate" putInt16
        rDataBuilder <- putResourceData cf rd
        let rdataLength = fromIntegral . LC8.length . BB.toLazyByteString $ rDataBuilder
        let rlenBuilder = BB.int16BE rdataLength
        return $ rlenBuilder <> rDataBuilder

getResourceRecords :: Int -> SGet [ResourceRecord]
getResourceRecords n = replicateM n getResourceRecord

getResourceRecord :: SGet ResourceRecord
getResourceRecord = do
    dom <- getDomain
    typ <- getTYPE
    cls <- getCLASS
    ttl <- getSeconds
    len <- getInt16
    dat <- getRData typ len
    return $ ResourceRecord dom typ cls ttl dat

getQuestions :: Int -> SGet [Question]
getQuestions n = replicateM n getQuestion

getQuestion :: SGet Question
getQuestion = Question <$> getDomain
                       <*> getTYPE
                       <*> getCLASS
