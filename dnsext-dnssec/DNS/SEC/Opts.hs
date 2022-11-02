{-# LANGUAGE PatternSynonyms #-}

module DNS.SEC.Opts (
    OptCode (
    DAU
  , DHU
  , N3U
  )
  , OD_DAU(..)
  , OD_DHU(..)
  , OD_N3U(..)
  , od_dau
  , od_dhu
  , od_n3u
  ) where

import DNS.Types
import DNS.Types.Internal

import DNS.SEC.Imports

-- | DNSSEC algorithm support (RFC6975, section 3)
pattern DAU  :: OptCode
pattern DAU   = OptCode 5
pattern DHU  :: OptCode
pattern DHU   = OptCode 6
pattern N3U  :: OptCode
pattern N3U   = OptCode 7

---------------------------------------------------------------

-- | DNSSEC Algorithm Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported DNSKEY algorithms.
newtype OD_DAU = OD_DAU [Word8] deriving (Eq)

instance Show OD_DAU where
    show (OD_DAU as) = _showAlgList "DAU" as

instance OptData OD_DAU where
    optDataCode _ = DAU
    encodeOptData (OD_DAU as) = putODWords (fromOptCode DAU) as
    decodeOptData _ len = OD_DAU <$> getNOctets len

od_dau :: [Word8] -> OData
od_dau a = toOData $ OD_DAU a

---------------------------------------------------------------

-- | DS Hash Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported DS hash algorithms.
newtype OD_DHU = OD_DHU [Word8] deriving (Eq)

instance Show OD_DHU where
    show (OD_DHU hs)    = _showAlgList "DHU" hs

instance OptData OD_DHU where
    optDataCode _ = DHU
    encodeOptData (OD_DHU hs) = putODWords (fromOptCode DHU) hs
    decodeOptData _ len = OD_DHU <$> getNOctets len

od_dhu :: [Word8] -> OData
od_dhu a = toOData $ OD_DHU a

---------------------------------------------------------------

-- | NSEC3 Hash Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported NSEC3 hash algorithms.
newtype OD_N3U = OD_N3U [Word8] deriving (Eq)

instance Show OD_N3U where
    show (OD_N3U hs)    = _showAlgList "N3U" hs

instance OptData OD_N3U where
    optDataCode _ = N3U
    encodeOptData (OD_N3U hs) = putODWords (fromOptCode N3U) hs
    decodeOptData _ len = OD_N3U <$> getNOctets len

od_n3u :: [Word8] -> OData
od_n3u a = toOData $ OD_N3U a

---------------------------------------------------------------

_showAlgList :: String -> [Word8] -> String
_showAlgList nm ws = nm ++ " " ++ intercalate "," (map show ws)

-- | Encode EDNS OPTION consisting of a list of octets.
putODWords :: Word16 -> [Word8] -> SPut
putODWords code ws =
     mconcat [ put16 code
             , putInt16 $ length ws
             , mconcat $ map put8 ws
             ]
