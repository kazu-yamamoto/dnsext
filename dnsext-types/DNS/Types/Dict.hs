{-# LANGUAGE ExistentialQuantification #-}

module DNS.Types.Dict where

import qualified Data.IntMap as M

import DNS.StateBinary
import DNS.Types.EDNS
import DNS.Types.Imports
import DNS.Types.Opaque
import DNS.Types.RData
import DNS.Types.Type

----------------------------------------------------------------

data DecodeDict = DecodeDict {
    rdataDict :: RDataDict
  , odataDict :: ODataDict
  }

defaultDecodeDict :: DecodeDict
defaultDecodeDict = DecodeDict defaultRDataDict defaultODataDict

addRData :: ResourceData a => TYPE -> Proxy a -> DecodeDict -> DecodeDict
addRData typ proxy dict = dict {
    rdataDict = M.insert (toKey typ) (RDataDecode proxy) (rdataDict dict)
  }

addOData :: OptData a => OptCode -> Proxy a -> DecodeDict -> DecodeDict
addOData code proxy dict = dict {
    odataDict = M.insert (toKeyO code) (ODataDecode proxy) (odataDict dict)
  }

----------------------------------------------------------------

getRData :: DecodeDict -> TYPE -> Int -> SGet RData
getRData dict OPT len = rd_opt <$> sGetMany "EDNS option" len getoption
  where
    getoption = do
        code <- toOptCode <$> get16
        olen <- getInt16
        getOData (odataDict dict) code olen
getRData dict typ len = case M.lookup (toKey typ) (rdataDict dict) of
    Nothing                  -> rd_unknown typ <$> getOpaque len
    Just (RDataDecode proxy) -> toRData <$> getResourceData proxy len

----------------------------------------------------------------

type RDataDict = M.IntMap RDataDecode

data RDataDecode = forall a . (ResourceData a) => RDataDecode (Proxy a)

toKey :: TYPE -> M.Key
toKey = fromIntegral . fromTYPE

defaultRDataDict :: RDataDict
defaultRDataDict =
    M.insert (toKey A)     (RDataDecode (Proxy :: Proxy RD_A)) $
    M.insert (toKey NS)    (RDataDecode (Proxy :: Proxy RD_NS)) $
    M.insert (toKey CNAME) (RDataDecode (Proxy :: Proxy RD_CNAME)) $
    M.insert (toKey SOA)   (RDataDecode (Proxy :: Proxy RD_SOA)) $
    M.insert (toKey NULL)  (RDataDecode (Proxy :: Proxy RD_NULL)) $
    M.insert (toKey PTR)   (RDataDecode (Proxy :: Proxy RD_PTR)) $
    M.insert (toKey MX)    (RDataDecode (Proxy :: Proxy RD_MX)) $
    M.insert (toKey TXT)   (RDataDecode (Proxy :: Proxy RD_TXT)) $
    M.insert (toKey RP)    (RDataDecode (Proxy :: Proxy RD_RP)) $
    M.insert (toKey AAAA)  (RDataDecode (Proxy :: Proxy RD_AAAA)) $
    M.insert (toKey SRV)   (RDataDecode (Proxy :: Proxy RD_SRV)) $
    M.insert (toKey DNAME) (RDataDecode (Proxy :: Proxy RD_DNAME)) $
    M.insert (toKey TLSA)  (RDataDecode (Proxy :: Proxy RD_TLSA)) $
    M.empty

----------------------------------------------------------------

type ODataDict = M.IntMap ODataDecode

data ODataDecode = forall a . (OptData a) => ODataDecode (Proxy a)

getOData :: ODataDict -> OptCode -> Int -> SGet OData
getOData dict code len = case M.lookup (toKeyO code) dict of
    Nothing                  -> od_unknown (fromOptCode code) <$> getOpaque len
    Just (ODataDecode proxy) -> toOData <$> decodeOptData proxy len

toKeyO :: OptCode -> M.Key
toKeyO = fromIntegral . fromOptCode

defaultODataDict :: ODataDict
defaultODataDict =
    M.insert (toKeyO NSID) (ODataDecode (Proxy :: Proxy OD_NSID)) $
    M.insert (toKeyO DAU)  (ODataDecode (Proxy :: Proxy OD_DAU)) $
    M.insert (toKeyO DHU)  (ODataDecode (Proxy :: Proxy OD_DHU)) $
    M.insert (toKeyO N3U)  (ODataDecode (Proxy :: Proxy OD_N3U)) $
    M.insert (toKeyO ClientSubnet)  (ODataDecode (Proxy :: Proxy OD_ClientSubnet)) $
    M.empty
