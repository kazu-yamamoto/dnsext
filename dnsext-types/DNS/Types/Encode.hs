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

import DNS.StateBinary
import DNS.Types.Domain
import DNS.Types.Imports
import DNS.Types.Message
import DNS.Types.RData

-- | Encode DNS message.
encode :: DNSMessage -> ByteString
encode = runSPut . putDNSMessage

-- | Encode DNS header.
encodeDNSHeader :: DNSHeader -> ByteString
encodeDNSHeader = runSPut . putHeader

-- | Encode DNS flags.
encodeDNSFlags :: DNSFlags -> ByteString
encodeDNSFlags = runSPut . putDNSFlags

-- | Encode a question.
encodeQuestion :: Question -> ByteString
encodeQuestion = runSPut . putQuestion Original

-- | Encode a resource record.
encodeResourceRecord :: ResourceRecord -> ByteString
encodeResourceRecord rr = runSPut $ putResourceRecord Original rr

-- | Encode a resource data.
encodeRData :: RData -> ByteString
encodeRData = runSPut . putRData Original

-- | Encode a domain with name compression.
encodeDomain :: Domain -> ByteString
encodeDomain = runSPut . putDomainRFC1035 Original

-- | Encode a mailbox name with name compression.
encodeMailbox :: Mailbox -> ByteString
encodeMailbox = runSPut . putMailboxRFC1035 Original
