{-# LANGUAGE PatternSynonyms #-}

module DNS.SEC.Opts (
    OptCode (
        DAU,
        DHU,
        N3U
    ),
    OD_DAU (..),
    OD_DHU (..),
    OD_N3U (..),
    od_dau,
    od_dhu,
    od_n3u,
    get_dau,
    get_dhu,
    get_n3u,
)
where

import DNS.SEC.HashAlg
import DNS.SEC.Imports
import DNS.SEC.PubAlg
import DNS.Types
import DNS.Types.Internal

-- | DNSSEC algorithm support (RFC6975, section 3)
pattern DAU :: OptCode
pattern DAU = OptCode 5

pattern DHU :: OptCode
pattern DHU = OptCode 6

pattern N3U :: OptCode
pattern N3U = OptCode 7

---------------------------------------------------------------

-- | DNSSEC Algorithm Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported DNSKEY algorithms.
newtype OD_DAU = OD_DAU [PubAlg] deriving (Eq)

instance Show OD_DAU where
    show (OD_DAU as) = _showAlgList "DAU" as

instance OptData OD_DAU where
    optDataCode _ = DAU
    optDataSize (OD_DAU as) = 4 + length as
    putOptData (OD_DAU as) = putODWords (fromOptCode DAU) $ map fromPubAlg as

get_dau :: Int -> Parser OD_DAU
get_dau len rbuf _ = OD_DAU . map toPubAlg <$> getNOctets rbuf len

od_dau :: [PubAlg] -> OData
od_dau a = toOData $ OD_DAU a

---------------------------------------------------------------

-- | DS Hash Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported DS hash algorithms.
newtype OD_DHU = OD_DHU [HashAlg] deriving (Eq)

instance Show OD_DHU where
    show (OD_DHU hs) = _showAlgList "DHU" hs

instance OptData OD_DHU where
    optDataCode _ = DHU
    optDataSize (OD_DHU hs) = 4 + length hs
    putOptData (OD_DHU hs) = putODWords (fromOptCode DHU) $ map fromHashAlg hs

get_dhu :: Int -> Parser OD_DHU
get_dhu len rbuf _ = OD_DHU . map toHashAlg <$> getNOctets rbuf len

od_dhu :: [HashAlg] -> OData
od_dhu a = toOData $ OD_DHU a

---------------------------------------------------------------

-- | NSEC3 Hash Understood (RFC6975).  Client to server.
-- (array of 8-bit numbers). Lists supported NSEC3 hash algorithms.
newtype OD_N3U = OD_N3U [HashAlg] deriving (Eq)

instance Show OD_N3U where
    show (OD_N3U hs) = _showAlgList "N3U" hs

instance OptData OD_N3U where
    optDataCode _ = N3U
    optDataSize (OD_N3U hs) = 4 + length hs
    putOptData (OD_N3U hs) = putODWords (fromOptCode N3U) $ map fromHashAlg hs

get_n3u :: Int -> Parser OD_N3U
get_n3u len rbuf _ = OD_N3U . map toHashAlg <$> getNOctets rbuf len

od_n3u :: [HashAlg] -> OData
od_n3u a = toOData $ OD_N3U a

---------------------------------------------------------------

_showAlgList :: Show a => String -> [a] -> String
_showAlgList nm ws = nm ++ " " ++ intercalate "," (map show ws)

-- | Encode EDNS OPTION consisting of a list of octets.
putODWords :: Word16 -> [Word8] -> Builder ()
putODWords code ws wbuf _ = do
    put16 wbuf code
    putInt16 wbuf $ length ws
    mapM_ (put8 wbuf) ws
