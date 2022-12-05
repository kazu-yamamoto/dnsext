{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

-- | This module provides Service Binding (SVCB) RR and HTTPS RR.
module DNS.SVCB (
  -- * Extension
    addResourceDataForSVCB
  -- ** DNS types
  , TYPE (
    SVCB
  , HTTPS
  )
  -- ** Resource data
  , RD_SVCB(..)
  , RD_HTTPS(..)
  , get_svcb
  , get_https
  -- * Service parameters
  , SvcParams
  , lookupSvcParams
  -- ** Service parameter keys
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
  -- ** Service parameter values
  , SvcParamValue
  , SPV(..)
  , SPV_Mandatory(..)
  , SPV_Port(..)
  , SPV_IPv4Hint(..)
  , SPV_IPv6Hint(..)
  , SPV_Opaque(..)
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
    putResourceData _ RD_SVCB{..} = do
        put16 svcb_priority
        -- https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-11#section-2.2
        -- "the uncompressed, fully-qualified TargetName"
        putDomain Canonical svcb_target
        let SvcParams m = svcb_params
        void $ M.foldrWithKey f (return ())  m
      where
        f k v x = encodekv k v >> x
        encodekv k v = do
            putInt16 k
            putInt16 $ Opaque.length v
            putOpaque v

get_svcb :: Int -> SGet RD_SVCB
get_svcb len = do
    end      <- (+) len <$> parserPosition
    priority <- get16
    target   <- getDomain
    pos      <- parserPosition
    params   <- newSvcParams <$> sGetMany "SVCB Param" (end - pos) svcparam
    return $ RD_SVCB priority target params
  where
    svcparam = do
        key <- getInt16 -- intestinally parsing as Int
        lng <- getInt16
        val <- getOpaque lng
        return (key, val)

----------------------------------------------------------------

data RD_HTTPS = RD_HTTPS {
    https_priority :: Word16
  , https_target   :: Domain
  , https_params   :: SvcParams
  } deriving (Eq,Ord,Show)

instance ResourceData RD_HTTPS where
    resourceDataType _ = HTTPS
    putResourceData cf (RD_HTTPS x y z) = putResourceData cf $ RD_SVCB x y z

get_https :: Int -> SGet RD_HTTPS
get_https len = do
    RD_SVCB x y z <- get_svcb len
    return $ RD_HTTPS x y z

----------------------------------------------------------------

addResourceDataForSVCB :: InitIO ()
addResourceDataForSVCB = do
  extendRR SVCB  "SVCB"  (\len -> toRData <$> get_svcb  len)
  extendRR HTTPS "HTTPS" (\len -> toRData <$> get_https len)
