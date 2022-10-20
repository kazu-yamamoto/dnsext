{-# LANGUAGE ExistentialQuantification #-}

module DNS.Types.Dict where

import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef')
import qualified Data.IntMap as M
import System.IO.Unsafe (unsafePerformIO)

import DNS.StateBinary
import DNS.Types.EDNS
import DNS.Types.Imports
import DNS.Types.Opaque
import DNS.Types.RData
import DNS.Types.Type

----------------------------------------------------------------

{-# NOINLINE globalRDataDict #-}
globalRDataDict :: IORef RDataDict
globalRDataDict = unsafePerformIO $ newIORef defaultRDataDict

{-# NOINLINE globalODataDict #-}
globalODataDict :: IORef ODataDict
globalODataDict = unsafePerformIO $ newIORef defaultODataDict

addRData :: ResourceData a => TYPE -> Proxy a -> IO ()
addRData typ proxy = atomicModifyIORef' globalRDataDict f
  where
    f dict = (M.insert (toKey typ) (RDataDecode proxy) dict, ())

addOData :: OptData a => OptCode -> Proxy a -> IO ()
addOData code proxy = atomicModifyIORef' globalODataDict f
  where
    f dict = (M.insert (toKeyO code) (ODataDecode proxy) dict, ())

----------------------------------------------------------------

getRData :: TYPE -> Int -> SGet RData
getRData OPT len = rd_opt <$> sGetMany "EDNS option" len getoption
  where
    dict = unsafePerformIO $ readIORef globalODataDict
    getoption = do
        code <- toOptCode <$> get16
        olen <- getInt16
        getOData dict code olen
getRData typ len = case M.lookup (toKey typ) dict of
    Nothing                  -> rd_unknown typ <$> getOpaque len
    Just (RDataDecode proxy) -> toRData <$> getResourceData proxy len
  where
    dict = unsafePerformIO $ readIORef globalRDataDict

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
    M.insert (toKey TLSA)  (RDataDecode (Proxy :: Proxy RD_TLSA))
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
    M.insert (toKeyO ClientSubnet)  (ODataDecode (Proxy :: Proxy OD_ClientSubnet))
    M.empty
