module DNS.Types.Encode (
  -- * Main encoder
    encode
  -- * Encoders for parts
  , encodeDNSMessage
  , encodeDNSHeader
  , encodeDNSFlags
  , encodeQuestion
  , encodeResourceRecord
  , encodeRData
  , encodeDomain
  , encodeMailbox
  ) where

import DNS.StateBinary
import DNS.Types.Domain
import DNS.Types.Imports
import DNS.Types.Message
import DNS.Types.RData

encode :: DNSMessage -> ByteString
encode = encodeDNSMessage

encodeDNSMessage :: DNSMessage -> ByteString
encodeDNSMessage = runSPut . putDNSMessage

-- | Encode DNS flags.
encodeDNSFlags :: DNSFlags -> ByteString
encodeDNSFlags = runSPut . putDNSFlags

encodeQuestion :: Question -> ByteString
encodeQuestion = runSPut . putQuestion

encodeRData :: RData -> ByteString
encodeRData = runSPut . putRData NoCanonical

-- | Encode DNS header.
encodeDNSHeader :: DNSHeader -> ByteString
encodeDNSHeader = runSPut . putHeader

-- | Encode a domain.
encodeDomain :: Domain -> ByteString
encodeDomain = runSPut . putDomain NoCanonical

-- | Encode a mailbox name.  The first label is separated from the remaining
-- labels by an @'\@'@ rather than a @.@.  This is used for the contact
-- address in the @SOA@ and @RP@ records.
--
encodeMailbox :: Mailbox -> ByteString
encodeMailbox = runSPut . putMailbox NoCanonical

-- | Encode a ResourceRecord.
encodeResourceRecord :: ResourceRecord -> ByteString
encodeResourceRecord rr = runSPut $ putResourceRecord NoCanonical rr
