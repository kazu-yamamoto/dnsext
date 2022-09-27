module DNS.Types (
  -- * DNS message
    DNSMessage(..)
  -- ** Header
  , DNSHeader(..)
  , Identifier
  , DNSFlags(..)
  , QorR(..)
  -- ** EDNS header
  , EDNSheader(..)
  , EDNS(..)
  , defaultEDNS
  -- * Resource record
  , ResourceRecord(..)
  , CLASS
  , TTL
  -- ** Sections
  , Question(..)
  , Answers
  , AuthorityRecords
  , AdditionalRecords
  -- * Resource data
  -- ** Types
  , RData
  , fromRData
  , toRData
  , rdataType
  -- ** Class
  , ResourceData
  -- ** Basic resource data
  , RD_A(..)
  , rd_a
  , RD_NS(..)
  , rd_ns
  , RD_CNAME(..)
  , rd_cname
  , RD_SOA
  , rd_soa
  , RD_NULL
  , rd_null
  , RD_PTR
  , rd_ptr
  , RD_MX
  , rd_mx
  , RD_TXT
  , rd_txt
  , RD_RP
  , rd_rp
  , RD_AAAA
  , rd_aaaa
  , RD_SRV
  , rd_srv
  , RD_DNAME
  , rd_dname
  , RD_OPT
  , rd_opt
  , RD_TLSA
  , rd_tlsa
  -- ** DNSSEC resource data
  , RD_RRSIG(..)
  , rd_rrsig
  , RD_DS(..)
  , rd_ds
  , RD_NSEC(..)
  , rd_nsec
  , RD_DNSKEY(..)
  , rd_dnskey
  , RD_NSEC3(..)
  , rd_nsec3
  , RD_NSEC3PARAM(..)
  , rd_nsec3param
  , RD_CDS(..)
  , rd_cds
  , RD_CDNSKEY(..)
  , rd_cdnskey
  -- * OPT resource data
  , OData(..)
  , odataToOptCode
  -- ** OptCode
  , OptCode (
    NSID
  , DAU
  , DHU
  , N3U
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
  , OD_DAU(..)
  , od_dau
  , OD_DHU(..)
  , od_dhu
  , OD_N3U(..)
  , od_n3u
  , OD_ClientSubnet(..)
  , od_clientSubnet
  , od_ecsGeneric
  , od_unknown
  -- * Basic types
  -- ** Domain
  , Domain
  , domainToByteString
  , byteStringToDomain
  , domainToText
  , textToDomain
  -- ** Mailbox
  , Mailbox
  , mailboxToByteString
  , byteStringToMailbox
  , mailboxToText
  , textToMailbox
  -- ** Opaque
  , Opaque
  , opaqueToByteString
  , byteStringToOpaque
  , opaqueToShortByteString
  , shortByteStringToOpaque
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
  )
  , fromRCODE
  , toRCODE
  -- ** Errors
  , DNSError(..)
  ) where

import DNS.Types.Domain
import DNS.Types.EDNS
import DNS.Types.Error
import DNS.Types.Message
import DNS.Types.Opaque
import DNS.Types.RData
import DNS.Types.Sec
import DNS.Types.Type
