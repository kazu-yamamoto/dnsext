-- | DNS message decoders.
--
-- When in doubt, use the 'decodeAt' or 'decodeManyAt' functions, which
-- correctly handle /circle-arithmetic/ DNS timestamps, e.g., in @RRSIG@
-- resource records.  The 'decode', and 'decodeMany' functions are only
-- appropriate in pure contexts when the current time is not available, and
-- @RRSIG@ records are not expected or desired.
--
-- The 'decodeMany' and 'decodeManyAt' functions decode a buffer holding one or
-- more messages, each preceded by 16-bit length in network byte order.  This
-- encoding is generally only appropriate for DNS TCP, and because TCP does not
-- preserve message boundaries, the decode is prepared to return a trailing
-- message fragment to be completed and retried when more input arrives from
-- network.
--
module DNS.Types.Decode (
    -- * Decoding a single DNS message
    EpochTime
  , decodeAt
  , decode
    -- * Decoding multple length-encoded DNS messages,
    -- e.g., from TCP traffic.
  , decodeManyAt
  , decodeMany
    -- * Decoders for parts
  , decodeDNSHeader
  , decodeDNSFlags
  , decodeQuestion
  , decodeResourceRecordAt
  , decodeResourceRecord
  , decodeRData
  , decodeDomain
  , decodeMailbox
  ) where

import qualified Data.ByteString as BS

import DNS.StateBinary
import DNS.Types.Dict
import DNS.Types.Domain
import DNS.Types.Error
import DNS.Types.Imports
import DNS.Types.Message
import DNS.Types.RData
import DNS.Types.Type

----------------------------------------------------------------

-- | Decode an input buffer containing a single encoded DNS message.  If the
-- input buffer has excess content beyond the end of the message an error is
-- returned.  DNS /circle-arithmetic/ timestamps (e.g. in RRSIG records) are
-- interpreted at the supplied epoch time.
--
decodeAt :: EpochTime                  -- ^ current epoch time
         -> ByteString                 -- ^ encoded input buffer
         -> Either DNSError DNSMessage -- ^ decoded message or error
decodeAt t bs = fst <$> runSGetAt t (fitSGet (BS.length bs) getDNSMessage) bs

-- | Decode an input buffer containing a single encoded DNS message.  If the
-- input buffer has excess content beyond the end of the message an error is
-- returned.  DNS /circle-arithmetic/ timestamps (e.g. in RRSIG records) are
-- interpreted based on a nominal time in the year 2073 chosen to maximize
-- the time range for which this gives correct translations of 32-bit epoch
-- times to absolute 64-bit epoch times.  This will yield incorrect results
-- starting circa 2141.
--
decode :: ByteString                 -- ^ encoded input buffer
       -> Either DNSError DNSMessage -- ^ decoded message or error
decode bs = fst <$> runSGet (fitSGet (BS.length bs) getDNSMessage) bs

-- | Decode a buffer containing multiple encoded DNS messages each preceded by
-- a 16-bit length in network byte order.  Any left-over bytes of a partial
-- message after the last complete message are returned as the second element
-- of the result tuple.  DNS /circle-arithmetic/ timestamps (e.g. in RRSIG
-- records) are interpreted at the supplied epoch time.
--
decodeManyAt :: EpochTime  -- ^ current epoch time
             -> ByteString -- ^ encoded input buffer
             -> Either DNSError ([DNSMessage], ByteString)
                           -- ^ decoded messages and left-over partial message
                           -- or error if any complete message fails to parse.
decodeManyAt t bs = decodeMParse (decodeAt t) bs

-- | Decode a buffer containing multiple encoded DNS messages each preceded by
-- a 16-bit length in network byte order.  Any left-over bytes of a partial
-- message after the last complete message are returned as the second element
-- of the result tuple.  DNS /circle-arithmetic/ timestamps (e.g. in RRSIG
-- records) are interpreted based on a nominal time in the year 2078 chosen to
-- give correct dates for DNS timestamps over a 136 year time range from the
-- date the root zone was signed on the 15th of July 2010 until the 21st of
-- August in 2146.  Outside this date range the output is off by some non-zero
-- multiple 2\^32 seconds.
--
decodeMany :: ByteString -- ^ encoded input buffer
           -> Either DNSError ([DNSMessage], ByteString)
                         -- ^ decoded messages and left-over partial message
                         -- or error if any complete message fails to parse.
decodeMany bs = decodeMParse decode bs


-- | Decode multiple messages using the given parser.
--
decodeMParse :: (ByteString -> Either DNSError DNSMessage)
                -- ^ message decoder
             -> ByteString
                -- ^ enoded input buffer
             -> Either DNSError ([DNSMessage], ByteString)
                -- ^ decoded messages and left-over partial message
                -- or error if any complete message fails to parse.
decodeMParse decoder bs = do
    ((bss, _), leftovers) <- runSGetWithLeftovers lengthEncoded bs
    msgs <- mapM decoder bss
    return (msgs, leftovers)
  where
    -- Read a list of length-encoded bytestrings
    lengthEncoded :: SGet [ByteString]
    lengthEncoded = many $ getInt16 >>= getNByteString

-- | Decode DNS header.
decodeDNSHeader :: ByteString -> Either DNSError DNSHeader
decodeDNSHeader bs = fst <$> runSGet getHeader bs

-- | Decode DNS flags.
decodeDNSFlags :: ByteString -> Either DNSError DNSFlags
decodeDNSFlags bs = fst <$> runSGet getDNSFlags bs


-- | Decode a question.
decodeQuestion :: ByteString -> Either DNSError Question
decodeQuestion bs = fst <$> runSGet getQuestion bs

-- | Decoding a resource record.

-- | Decode a resource record (RR) with any DNS timestamps interpreted at the
-- nominal epoch time (see 'decodeAt').  Since RRs may use name compression,
-- it is not generally possible to decode resource record separately from the
-- enclosing DNS message.  This is an internal function.
--
decodeResourceRecord :: ByteString -> Either DNSError ResourceRecord
decodeResourceRecord bs = fst <$> runSGet getResourceRecord bs

-- | Decode a resource record with DNS timestamps interpreted at the
-- supplied epoch time.  Since RRs may use DNS name compression, it is not
-- generally possible to decode resource record separately from the enclosing
-- DNS message.  This is an internal function.
--
decodeResourceRecordAt :: EpochTime  -- ^ current epoch time
                       -> ByteString -- ^ encoded resource record
                       -> Either DNSError ResourceRecord
decodeResourceRecordAt t bs = fst <$> runSGetAt t getResourceRecord bs

-- | Decode a resource data.
decodeRData :: TYPE -> ByteString -> Either DNSError RData
decodeRData typ bs = fst <$> runSGet (getRData typ len) bs
  where
    len = BS.length bs

-- | Decode a domain name.  Since DNS names may use name compression, it is not
-- generally possible to decode the names separately from the enclosing DNS
-- message.  This is an internal function exposed only for testing.
--
decodeDomain :: ByteString -> Either DNSError Domain
decodeDomain bs = fst <$> runSGet getDomain bs

-- | Decode a mailbox name (e.g. the SOA record /rname/ field).  Since DNS names
-- may use name compression, it is not generally possible to decode the names
-- separately from the enclosing DNS message.  This is an internal function.
--
decodeMailbox :: ByteString -> Either DNSError Mailbox
decodeMailbox bs = fst <$> runSGet getMailbox bs
