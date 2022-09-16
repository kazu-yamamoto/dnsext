{-# LANGUAGE PatternSynonyms #-}

module DNS.Types.Base (
    Domain
  , Mailbox
  , TYPE (
    A
  , NS
  , CNAME
  , SOA
  , NULL
  , PTR
  , MX
  , TXT
  , RP
  , AAAA
  , SRV
  , DNAME
  , OPT
  , DS
  , RRSIG
  , NSEC
  , DNSKEY
  , NSEC3
  , NSEC3PARAM
  , TLSA
  , CDS
  , CDNSKEY
  , CSYNC
  , AXFR
  , ANY
  , CAA
  )
  , fromTYPE
  , toTYPE
  , DNSError(..)
  , _b16encode
  , _b32encode
  , _b64encode
  ) where

import Control.Exception (Exception, IOException)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C8

import qualified DNS.Types.Base32Hex as B32
import DNS.Types.Imports

----------------------------------------------------------------

-- | This type holds the /presentation form/ of fully-qualified DNS domain
-- names encoded as ASCII A-labels, with \'.\' separators between labels.
-- Non-printing characters are escaped as @\\DDD@ (a backslash, followed by
-- three decimal digits). The special characters: @ \", \$, (, ), ;, \@,@ and
-- @\\@ are escaped by prepending a backslash.  The trailing \'.\' is optional
-- on input, but is recommended, and is always added when decoding from
-- /wire form/.
--
-- The encoding of domain names to /wire form/, e.g. for transmission in a
-- query, requires the input encodings to be valid, otherwise a 'DecodeError'
-- may be thrown. Domain names received in wire form in DNS messages are
-- escaped to this presentation form as part of decoding the 'DNSMessage'.
--
-- This form is ASCII-only. Any conversion between A-label 'ByteString's,
-- and U-label 'Text' happens at whatever layer maps user input to DNS
-- names, or presents /friendly/ DNS names to the user.  Not all users
-- can read all scripts, and applications that default to U-label form
-- should ideally give the user a choice to see the A-label form.
-- Examples:
--
-- @
-- www.example.org.           -- Ordinary DNS name.
-- \_25.\_tcp.mx1.example.net.  -- TLSA RR initial labels have \_ prefixes.
-- \\001.exotic.example.       -- First label is Ctrl-A!
-- just\\.one\\.label.example.  -- First label is \"just.one.label\"
-- @
--
type Domain = ByteString

-- | Type for a mailbox encoded on the wire as a DNS name, but the first label
-- is conceptually the local part of an email address, and may contain internal
-- periods that are not label separators. Therefore, in mailboxes \@ is used as
-- the separator between the first and second labels, and any \'.\' characters
-- in the first label are not escaped.  The encoding is otherwise the same as
-- 'Domain' above. This is most commonly seen in the /rname/ of @SOA@ records,
-- and is also employed in the @mbox-dname@ field of @RP@ records.
-- On input, if there is no unescaped \@ character in the 'Mailbox', it is
-- reparsed with \'.\' as the first label separator. Thus the traditional
-- format with all labels separated by dots is also accepted, but decoding from
-- wire form always uses \@ between the first label and the domain-part of the
-- address.  Examples:
--
-- @
-- hostmaster\@example.org.  -- First label is simply @hostmaster@
-- john.smith\@examle.com.   -- First label is @john.smith@
-- @
--
type Mailbox = ByteString

----------------------------------------------------------------

-- | Types for resource records.
newtype TYPE = TYPE {
    -- | From type to number.
    fromTYPE :: Word16
  } deriving (Eq, Ord)

-- https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4

-- | IPv4 address
pattern A :: TYPE
pattern A          = TYPE   1
-- | An authoritative name serve
pattern NS :: TYPE
pattern NS         = TYPE   2
-- | The canonical name for an alias
pattern CNAME :: TYPE
pattern CNAME      = TYPE   5
-- | Marks the start of a zone of authority
pattern SOA :: TYPE
pattern SOA        = TYPE   6
-- | A null RR (EXPERIMENTAL)
pattern NULL :: TYPE
pattern NULL       = TYPE  10
-- | A domain name pointer
pattern PTR :: TYPE
pattern PTR        = TYPE  12
-- | Mail exchange
pattern MX :: TYPE
pattern MX         = TYPE  15
-- | Text strings
pattern TXT :: TYPE
pattern TXT        = TYPE  16
-- | Responsible Person
pattern RP :: TYPE
pattern RP         = TYPE  17
-- | IPv6 Address
pattern AAAA :: TYPE
pattern AAAA       = TYPE  28
-- | Server Selection (RFC2782)
pattern SRV :: TYPE
pattern SRV        = TYPE  33
-- | DNAME (RFC6672)
pattern DNAME :: TYPE
pattern DNAME      = TYPE  39 -- RFC 6672
-- | OPT (RFC6891)
pattern OPT :: TYPE
pattern OPT        = TYPE  41 -- RFC 6891
-- | Delegation Signer (RFC4034)
pattern DS :: TYPE
pattern DS         = TYPE  43 -- RFC 4034
-- | RRSIG (RFC4034)
pattern RRSIG :: TYPE
pattern RRSIG      = TYPE  46 -- RFC 4034
-- | NSEC (RFC4034)
pattern NSEC :: TYPE
pattern NSEC       = TYPE  47 -- RFC 4034
-- | DNSKEY (RFC4034)
pattern DNSKEY :: TYPE
pattern DNSKEY     = TYPE  48 -- RFC 4034
-- | NSEC3 (RFC5155)
pattern NSEC3 :: TYPE
pattern NSEC3      = TYPE  50 -- RFC 5155
-- | NSEC3PARAM (RFC5155)
pattern NSEC3PARAM :: TYPE
pattern NSEC3PARAM = TYPE  51 -- RFC 5155
-- | TLSA (RFC6698)
pattern TLSA :: TYPE
pattern TLSA       = TYPE  52 -- RFC 6698
-- | Child DS (RFC7344)
pattern CDS :: TYPE
pattern CDS        = TYPE  59 -- RFC 7344
-- | DNSKEY(s) the Child wants reflected in DS (RFC7344)
pattern CDNSKEY :: TYPE
pattern CDNSKEY    = TYPE  60 -- RFC 7344
-- | Child-To-Parent Synchronization (RFC7477)
pattern CSYNC :: TYPE
pattern CSYNC      = TYPE  62 -- RFC 7477
-- | Zone transfer (RFC5936)
pattern AXFR :: TYPE
pattern AXFR       = TYPE 252 -- RFC 5936
-- | A request for all records the server/cache has available
pattern ANY :: TYPE
pattern ANY        = TYPE 255
-- | Certification Authority Authorization (RFC6844)
pattern CAA :: TYPE
pattern CAA        = TYPE 257 -- RFC 6844

-- | From number to type.
toTYPE :: Word16 -> TYPE
toTYPE = TYPE

instance Show TYPE where
    show A          = "A"
    show NS         = "NS"
    show CNAME      = "CNAME"
    show SOA        = "SOA"
    show NULL       = "NULL"
    show PTR        = "PTR"
    show MX         = "MX"
    show TXT        = "TXT"
    show RP         = "RP"
    show AAAA       = "AAAA"
    show SRV        = "SRV"
    show DNAME      = "DNAME"
    show OPT        = "OPT"
    show DS         = "DS"
    show RRSIG      = "RRSIG"
    show NSEC       = "NSEC"
    show DNSKEY     = "DNSKEY"
    show NSEC3      = "NSEC3"
    show NSEC3PARAM = "NSEC3PARAM"
    show TLSA       = "TLSA"
    show CDS        = "CDS"
    show CDNSKEY    = "CDNSKEY"
    show CSYNC      = "CSYNC"
    show AXFR       = "AXFR"
    show ANY        = "ANY"
    show CAA        = "CAA"
    show (TYPE n)   = "TYPE " ++ show n

----------------------------------------------------------------

-- | An enumeration of all possible DNS errors that can occur.
data DNSError =
    -- | The sequence number of the answer doesn't match our query. This
    --   could indicate foul play.
    SequenceNumberMismatch
    -- | The question section of the response doesn't match our query. This
    --   could indicate foul play.
  | QuestionMismatch
    -- | A zone tranfer, i.e., a request of type AXFR, was attempted with the
    -- "lookup" interface. Zone transfer is different enough from "normal"
    -- requests that it requires a different interface.
  | InvalidAXFRLookup
    -- | The number of retries for the request was exceeded.
  | RetryLimitExceeded
    -- | TCP fallback request timed out.
  | TimeoutExpired
    -- | The answer has the correct sequence number, but returned an
    --   unexpected RDATA format.
  | UnexpectedRDATA
    -- | The domain for query is illegal.
  | IllegalDomain
    -- | The name server was unable to interpret the query.
  | FormatError
    -- | The name server was unable to process this query due to a
    --   problem with the name server.
  | ServerFailure
    -- | This code signifies that the domain name referenced in the
    --   query does not exist.
  | NameError
    -- | The name server does not support the requested kind of query.
  | NotImplemented
    -- | The name server refuses to perform the specified operation for
    --   policy reasons.  For example, a name
    --   server may not wish to provide the
    --   information to the particular requester,
    --   or a name server may not wish to perform
    --   a particular operation (e.g., zone transfer) for particular data.
  | OperationRefused
    -- | The server does not support the OPT RR version or content
  | BadOptRecord
    -- | Configuration is wrong.
  | BadConfiguration
    -- | Network failure.
  | NetworkFailure IOException
    -- | Error is unknown
  | DecodeError String
  | UnknownDNSError
  deriving (Eq, Show, Typeable)

instance Exception DNSError

----------------------------------------------------------------

_b16encode, _b32encode, _b64encode :: ByteString -> String
_b16encode = C8.unpack. B16.encode
_b32encode = C8.unpack. B32.encode
_b64encode = C8.unpack. B64.encode
