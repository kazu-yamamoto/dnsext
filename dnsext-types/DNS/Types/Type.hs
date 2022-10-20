{-# LANGUAGE PatternSynonyms #-}

module DNS.Types.Type (
    TYPE (
    TYPE
  , A
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
  , getTYPE
  , putTYPE
  ) where

import Data.IORef (IORef, newIORef, readIORef)
import Data.IntMap (IntMap)
import qualified Data.IntMap as M
import System.IO.Unsafe (unsafePerformIO)

import DNS.StateBinary
import DNS.Types.Imports

----------------------------------------------------------------

-- | Types for resource records.
newtype TYPE = TYPE {
    -- | From type to number.
    fromTYPE :: Word16
  } deriving (Eq, Ord)

-- | From number to type.
toTYPE :: Word16 -> TYPE
toTYPE = TYPE

----------------------------------------------------------------

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
-- | TLSA (RFC6698)
pattern TLSA :: TYPE
pattern TLSA       = TYPE  52 -- RFC 6698
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

----------------------------------------------------------------

instance Show TYPE where
    show (TYPE w) = case M.lookup i dict of
      Nothing   -> "TYPE " ++ show w
      Just name -> name
      where
        i = fromIntegral w
        dict = unsafePerformIO $ readIORef globalTypeDict

type TypeDict = IntMap String

insertTypeDict :: TYPE -> String -> TypeDict -> TypeDict
insertTypeDict (TYPE w) name dict = M.insert i name dict
  where
    i = fromIntegral w

defaultTypeDict :: IntMap String
defaultTypeDict =
    insertTypeDict A     "A"
  $ insertTypeDict NS    "NS"
  $ insertTypeDict CNAME "CNAME"
  $ insertTypeDict SOA   "SOA"
  $ insertTypeDict NULL  "NULL"
  $ insertTypeDict PTR   "PTR"
  $ insertTypeDict MX    "MX"
  $ insertTypeDict TXT   "TXT"
  $ insertTypeDict RP    "RP"
  $ insertTypeDict AAAA  "AAAA"
  $ insertTypeDict SRV   "SRV"
  $ insertTypeDict DNAME "DNAME"
  $ insertTypeDict OPT   "OPT"
  $ insertTypeDict TLSA  "TLSA"
  $ insertTypeDict CSYNC "CSYNC"
  $ insertTypeDict AXFR  "AXFR"
  $ insertTypeDict ANY   "ANY"
  $ insertTypeDict CAA   "CAA"
    M.empty

{-# NOINLINE globalTypeDict #-}
globalTypeDict :: IORef (IntMap String)
globalTypeDict = unsafePerformIO $ newIORef defaultTypeDict

----------------------------------------------------------------

getTYPE :: SGet TYPE
getTYPE = toTYPE <$> get16

putTYPE :: TYPE -> SPut
putTYPE x = put16 $ fromTYPE x
