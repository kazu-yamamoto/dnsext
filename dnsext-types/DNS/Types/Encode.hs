module DNS.Types.Encode (
    -- * Main encoder
    encode,

    -- * Encoders for parts
    encodeDNSHeader,
    encodeDNSFlags,
    encodeQuestion,
    encodeResourceRecord,
    encodeRData,
    encodeDomain,
    encodeMailbox,
) where

import DNS.Wire
import DNS.Types.Domain
import DNS.Types.Imports
import DNS.Types.Message
import DNS.Types.RData

-- | Encode DNS message.
encode :: DNSMessage -> ByteString
encode = runBuilder . putDNSMessage

-- | Encode DNS header.
encodeDNSHeader :: DNSHeader -> ByteString
encodeDNSHeader = runBuilder . putHeader

-- | Encode DNS flags.
encodeDNSFlags :: DNSFlags -> ByteString
encodeDNSFlags = runBuilder . putDNSFlags

-- | Encode a question.
encodeQuestion :: Question -> ByteString
encodeQuestion = runBuilder . putQuestion Original

-- | Encode a resource record.
encodeResourceRecord :: ResourceRecord -> ByteString
encodeResourceRecord rr = runBuilder $ putResourceRecord Original rr

-- | Encode a resource data.
encodeRData :: RData -> ByteString
encodeRData = runBuilder . putRData Original

-- | Encode a domain with name compression.
encodeDomain :: Domain -> ByteString
encodeDomain = runBuilder . putDomainRFC1035 Original

-- | Encode a mailbox name with name compression.
encodeMailbox :: Mailbox -> ByteString
encodeMailbox = runBuilder . putMailboxRFC1035 Original
