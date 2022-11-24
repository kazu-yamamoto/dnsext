module DNS.Types (
  -- * DNS message
    DNSMessage(..)
  , fromDNSMessage
  , defaultQuery
  , makeQuery
  , defaultResponse
  , makeResponse
  -- ** Header
  , DNSHeader(..)
  , Identifier
  , DNSFlags(..)
  , defaultDNSFlags
  , QorR(..)
  -- ** EDNS header
  , EDNSheader(..)
  , EDNS(..)
  , defaultEDNS
  , minUdpSize
  , maxUdpSize
  -- * Question
  , Question(..)
  , CLASS
  , classIN
  -- * Resource record
  , ResourceRecord(..)
  , TTL
  -- ** Sections
  , Answers
  , AuthorityRecords
  , AdditionalRecords
  -- * Resource data
  -- ** Types
  , RData
  , fromRData
  , toRData
  , rdataType
  , rdataField
  -- ** Class
  , ResourceData
  -- ** Basic resource data
  -- *** A RR
  , RD_A
  , rd_a
  , a_ipv4
  -- *** NS RR
  , RD_NS
  , rd_ns
  , ns_domain
  -- *** CNAME RR
  , RD_CNAME
  , rd_cname
  , cname_domain
  -- *** SOA RR
  , RD_SOA
  , rd_soa
  , soa_mname
  , soa_rname
  , soa_serial
  , soa_refresh
  , soa_retry
  , soa_expire
  , soa_minimum
  -- *** NULL RR
  , RD_NULL
  , rd_null
  , null_opaque
  -- *** PTR RR
  , RD_PTR
  , rd_ptr
  , ptr_domain
  -- *** MX RR
  , RD_MX
  , rd_mx
  , mx_preference
  , mx_exchange
  -- *** TXT RR
  , RD_TXT
  , rd_txt
  , txt_opaque
  -- *** RP RR
  , RD_RP
  , rd_rp
  , rp_mbox
  , rp_domain
  -- *** AAAA RR
  , RD_AAAA
  , rd_aaaa
  , aaaa_ipv6
  -- *** SRV RR
  , RD_SRV
  , rd_srv
  , srv_priority
  , srv_weight
  , srv_port
  , srv_target
  -- *** DNAME RR
  , RD_DNAME
  , rd_dname
  , dname_target
  -- *** OPT RR
  , RD_OPT
  , rd_opt
  , opt_odata
  -- *** TLSA RR
  , RD_TLSA
  , rd_tlsa
  , tlsa_usage
  , tlsa_selector
  , tlsa_matching_type
  , tlsa_assoc_data
  -- * OPT resource data
  , OData(..)
  , odataToOptCode
  -- ** OptCode
  , OptCode (
    NSID
  , ClientSubnet
  )
  , fromOptCode
  , toOptCode
  -- ** OptData
  , OptData
  , fromOData
  , toOData
  -- ** Optional data
  , OD_NSID(..)
  , od_nsid
  , OD_ClientSubnet(..)
  , od_clientSubnet
  , od_ecsGeneric
  , od_unknown
  -- * Basic types
  , CaseInsensitiveName(..)
  -- ** Domain
  , Domain
  , putDomain
  , getDomain
  , checkDomain
  , modifyDomain
  , addRoot
  , dropRoot
  , hasRoot
  , isIllegal
  , superDomains
  , isSubDomainOf
  -- ** Mailbox
  , Mailbox
  , checkMailbox
  , modifyMailbox
  , putMailbox
  , getMailbox
  -- ** Opaque
  , Opaque
  -- ** TYPE
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
  , TLSA
  , CSYNC
  , AXFR
  , ANY
  , CAA
  )
  , fromTYPE
  , toTYPE
  -- ** OPCODE
  , OPCODE(
    OP_STD
  , OP_INV
  , OP_SSR
  , OP_NOTIFY
  , OP_UPDATE
  )
  -- ** RCODE
  , RCODE(
    NoErr
  , FormatErr
  , ServFail
  , NameErr
  , NotImpl
  , Refused
  , YXDomain
  , YXRRSet
  , NXRRSet
  , NotAuth
  , NotZone
  , BadVers
  , BadKey
  , BadTime
  , BadMode
  , BadName
  , BadAlg
  , BadTrunc
  , BadCookie
  , BadRCODE
  )
  , fromRCODE
  , toRCODE
  -- ** Errors
  , DNSError(..)
  -- ** Seconds
  , Seconds(..)
  -- * Extension
  , InitIO
  , runInitIO
  ) where

import DNS.Types.Dict
import DNS.Types.Domain
import DNS.Types.EDNS
import DNS.Types.Error
import DNS.Types.Message
import DNS.Types.Opaque
import DNS.Types.RData
import DNS.Types.Seconds
import DNS.Types.Type

----------------------------------------------------------------

-- | Messages with a non-error RCODE are passed to the supplied function
-- for processing.  Other messages are translated to 'DNSError' instances.
--
-- Note that 'NameError' is not a lookup error.  The lookup is successful,
-- bearing the sad news that the requested domain does not exist.  'NameError'
-- responses may return a meaningful AD bit, may contain useful data in the
-- authority section, and even initial CNAME records that lead to the
-- ultimately non-existent domain.  Applications that wish to process the
-- content of 'NameError' (NXDomain) messages will need to implement their
-- own RCODE handling.
--
fromDNSMessage :: DNSMessage -> (DNSMessage -> a) -> Either DNSError a
fromDNSMessage ans conv = case errcode ans of
    NoErr     -> Right $ conv ans
    FormatErr -> Left FormatError
    ServFail  -> Left ServerFailure
    NameErr   -> Left NameError
    NotImpl   -> Left NotImplemented
    Refused   -> Left OperationRefused
    BadVers   -> Left BadOptRecord
    BadRCODE  -> Left $ DecodeError "Malformed EDNS message"
    _         -> Left UnknownDNSError
  where
    errcode = rcode . flags . header
