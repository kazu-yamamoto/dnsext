module DNS.Types.Error where

import Control.Exception (Exception, SomeException)

----------------------------------------------------------------

-- | An enumeration of all possible DNS errors that can occur.
data DNSError
    = -- | The sequence number of the answer doesn't match our query. This
      --   could indicate foul play.
      SequenceNumberMismatch
    | -- | The question section of the response doesn't match our query. This
      --   could indicate foul play.
      QuestionMismatch
    | -- | A zone tranfer, i.e., a request of type AXFR, was attempted with the
      -- "lookup" interface. Zone transfer is different enough from "normal"
      -- requests that it requires a different interface.
      InvalidAXFRLookup
    | -- | The number of retries for the request was exceeded.
      RetryLimitExceeded
    | -- | TCP fallback request timed out.
      TimeoutExpired
    | -- | The answer has the correct sequence number, but returned an
      --   unexpected RDATA format.
      UnexpectedRDATA
    | -- | The domain for query is illegal.
      IllegalDomain
    | -- | The name server was unable to interpret the query.
      FormatError
    | -- | The name server was unable to process this query due to a
      --   problem with the name server.
      ServerFailure
    | -- | This code signifies that the domain name referenced in the
      --   query does not exist.
      NameError
    | -- | The name server does not support the requested kind of query.
      NotImplemented
    | -- | The name server refuses to perform the specified operation for
      --   policy reasons.  For example, a name
      --   server may not wish to provide the
      --   information to the particular requester,
      --   or a name server may not wish to perform
      --   a particular operation (e.g., zone transfer) for particular data.
      OperationRefused
    | -- | The server does not support the OPT RR version or content
      BadOptRecord
    | -- | Configuration is wrong.
      BadConfiguration
    | -- | Network failure.
      NetworkFailure SomeException String
    | -- | Bad thing happens.
      BadThing String -- SomeException cannot be used due to Eq
    | -- | Wire format cannot be decoded.
      DecodeError String
    | -- | Additional DNSError info
      DNSErrorInfo DNSError ~String
    | -- | Error is unknown
      UnknownDNSError
    deriving (Show)

{- FOURMOLU_DISABLE -}
-- SomeException is not an instance of Eq.
instance Eq DNSError where
    SequenceNumberMismatch == SequenceNumberMismatch = True
    QuestionMismatch       == QuestionMismatch       = True
    InvalidAXFRLookup      == InvalidAXFRLookup      = True
    RetryLimitExceeded     == RetryLimitExceeded     = True
    TimeoutExpired         == TimeoutExpired         = True
    UnexpectedRDATA        == UnexpectedRDATA        = True
    IllegalDomain          == IllegalDomain          = True
    FormatError            == FormatError            = True
    ServerFailure          == ServerFailure          = True
    NameError              == NameError              = True
    NotImplemented         == NotImplemented         = True
    OperationRefused       == OperationRefused       = True
    BadOptRecord           == BadOptRecord           = True
    BadConfiguration       == BadConfiguration       = True
    NetworkFailure _ s1    == NetworkFailure _ s2    = s1 == s2
    BadThing s1            == BadThing s2            = s1 == s2
    DecodeError s1         == DecodeError s2         = s1 == s2
    DNSErrorInfo e1 s1     == DNSErrorInfo e2 s2     = e1 == e2 && s1 == s2
    UnknownDNSError        == UnknownDNSError        = True
    _                      == _                      = False
{- FOURMOLU_ENABLE -}

instance Exception DNSError

{- FOURMOLU_DISABLE -}
-- |
-- >>> unwrapDNSErrorInfo (DNSErrorInfo RetryLimitExceeded "with \"foo.example.\" A")
-- (RetryLimitExceeded,["with \"foo.example.\" A"])
unwrapDNSErrorInfo :: DNSError -> (DNSError, [String])
unwrapDNSErrorInfo = go id
  where
    go a (DNSErrorInfo e s) = go (a . (s:)) e
    go a e                  = (e, a [])
{- FOURMOLU_ENABLE -}
