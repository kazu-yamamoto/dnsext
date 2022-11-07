{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.SVCB (
    TYPE (
    SVCB
  , HTTPS
  )
  , RD_SVCB(..)
  , RD_HTTPS(..)
  , SvcParams
  , SvcParamKey (
    SPK_Mandatory
  , SPK_ALPN
  , SPK_NoDefaultALPN
  , SPK_Port
  , SPK_IPv4Hint
  , SPK_ECH
  , SPK_IPv6Hint
  )
  , fromSvcParamKey
  , toSvcParamKey
  , SvcParamValue
  , lookupSvcParams
  , addResourceDataForSVCB
  ) where

import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque
import qualified Data.IntMap as M

import DNS.SVCB.Imports
import DNS.SVCB.Key
import DNS.SVCB.Params
import DNS.SVCB.Value

----------------------------------------------------------------

pattern SVCB :: TYPE
pattern SVCB  = TYPE 64

pattern HTTPS :: TYPE
pattern HTTPS = TYPE 65

----------------------------------------------------------------

data RD_SVCB = RD_SVCB {
    svcb_priority :: Word16
  , svcb_target   :: Domain
  , svcb_params   :: SvcParams
  } deriving (Eq,Ord,Show)

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

----------------------------------------------------------------

newtype RD_HTTPS = RD_HTTPS RD_SVCB deriving (Eq,Ord,Show)

instance ResourceData RD_HTTPS where
    resourceDataType _ = HTTPS
    putResourceData cf (RD_HTTPS r) = putResourceData cf r
    getResourceData _ lim = RD_HTTPS <$> getResourceData (Proxy :: Proxy RD_SVCB) lim

----------------------------------------------------------------

addResourceDataForSVCB :: InitIO ()
addResourceDataForSVCB = do
  extendRR SVCB  "SVCB"  (Proxy :: Proxy RD_SVCB)
  extendRR HTTPS "HTTPS" (Proxy :: Proxy RD_HTTPS)
