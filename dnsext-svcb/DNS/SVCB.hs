{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.SVCB where

import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque
import Data.IntMap (IntMap)
import qualified Data.IntMap as M

import DNS.SVCB.Imports

data RD_SVCB = RD_SVCB {
    svcb_priority :: Word16
  , svcb_target   :: Domain
  , svcb_params   :: SvcParams
  } deriving (Eq,Ord,Show)

newtype SvcParams = SvcParams (IntMap SvcParamValue) deriving (Eq, Ord)

instance Show SvcParams where
    show (SvcParams m) = "[" ++ intercalate ", " (M.foldrWithKey f [] m) ++ "]"
      where
        showkv k v = show (toSvcParamKey $ fromIntegral k) ++ "=" ++ show v
        f k v xs = showkv k v : xs

lookupSvcParams :: SvcParamKey -> SvcParams -> Maybe SvcParamValue
lookupSvcParams key (SvcParams m) = M.lookup k m
  where
    k = fromIntegral $ fromSvcParamKey key

newSvcParams :: [(Int,SvcParamValue)] -> SvcParams
newSvcParams kvs = SvcParams $ foldr ins M.empty kvs
  where
    ins (k,v) = M.insert k v

newtype SvcParamKey = SvcParamKey {
    fromSvcParamKey :: Word16
  } deriving (Eq, Ord)

instance Show SvcParamKey where
    show SPK_Mandatory     = "mandatory"
    show SPK_ALPN          = "alpn"
    show SPK_NoDefaultALPN = "no-adefault-alpn"
    show SPK_Port          = "port"
    show SPK_IPv4Hint      = "ipv4hint"
    show SPK_ECH           = "ech"
    show SPK_IPv6Hint      = "ipv6hint"
    show (SvcParamKey n)   = "SvcParamKey" ++ show n -- no space

toSvcParamKey :: Word16 -> SvcParamKey
toSvcParamKey = SvcParamKey

type SvcParamValue = Opaque

pattern SPK_Mandatory     :: SvcParamKey
pattern SPK_Mandatory      = SvcParamKey 0

pattern SPK_ALPN          :: SvcParamKey
pattern SPK_ALPN           = SvcParamKey 1

pattern SPK_NoDefaultALPN :: SvcParamKey
pattern SPK_NoDefaultALPN  = SvcParamKey 2

pattern SPK_Port          :: SvcParamKey
pattern SPK_Port           = SvcParamKey 3

pattern SPK_IPv4Hint      :: SvcParamKey
pattern SPK_IPv4Hint       = SvcParamKey 4

pattern SPK_ECH           :: SvcParamKey
pattern SPK_ECH            = SvcParamKey 5

pattern SPK_IPv6Hint      :: SvcParamKey
pattern SPK_IPv6Hint       = SvcParamKey 6


pattern SVCB :: TYPE
pattern SVCB  = TYPE 64

pattern HTTPS :: TYPE
pattern HTTPS = TYPE 65

addResourceDataForSVCB :: InitIO ()
addResourceDataForSVCB = do
  extendRR SVCB  "SVCB"  (Proxy :: Proxy RD_SVCB)
  extendRR HTTPS "HTTPS" (Proxy :: Proxy RD_HTTPS)

newtype RD_HTTPS = RD_HTTPS RD_SVCB deriving (Eq,Ord,Show)

instance ResourceData RD_HTTPS where
    resourceDataType _ = HTTPS
    putResourceData cf (RD_HTTPS r) = putResourceData cf r
    getResourceData _ lim = RD_HTTPS <$> getResourceData (Proxy :: Proxy RD_SVCB) lim

instance ResourceData RD_SVCB where
    resourceDataType _ = SVCB
    putResourceData _ RD_SVCB{..} =
        mconcat ( put16 svcb_priority :
                  putDomain Canonical svcb_target :
                  putSvcParams svcb_params
                  )
          where
            putSvcParams (SvcParams m) = M.foldrWithKey f [] m
            f k v xs = encodekv k v : xs
            encodekv k v = mconcat [ putInt16 k
                                   , putInt16 (Opaque.length v)
                                   , putOpaque v ]
    getResourceData _ lim = do
        end      <- (+) lim <$> parserPosition
        priority <- get16
        target   <- getDomain
        pos      <- parserPosition
        params   <- newSvcParams <$> sGetMany "SVCB Param" (end - pos) svcparam
        return $ RD_SVCB priority target params
      where
        svcparam = do
            key <- getInt16 -- intestinally parsing as Int
            len <- getInt16
            val <- getOpaque len
            return (key, val)
