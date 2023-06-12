{-# LANGUAGE OverloadedStrings #-}

module DNS.SVCB.Value where

import DNS.SVCB.Imports
import DNS.SVCB.Key
import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import Data.IP
import Network.Socket (PortNumber)

----------------------------------------------------------------

newtype SvcParamValue = SvcParamValue Opaque deriving (Show, Eq, Ord)

----------------------------------------------------------------

class SPV a where
    fromSvcParamValue :: SvcParamValue -> Maybe a
    toSvcParamValue :: a -> SvcParamValue

toSPV :: SPut () -> SvcParamValue
toSPV = SvcParamValue . Opaque.fromByteString . runSPut

fromSPV :: (Int -> SGet a) -> SvcParamValue -> Maybe a
fromSPV parser (SvcParamValue o) = case runSGet (parser len) bs of
    Right (r, _) -> Just r
    _ -> Nothing
  where
    bs = Opaque.toByteString o
    len = Opaque.length o

----------------------------------------------------------------

newtype SPV_Mandatory = SPV_Mandatory
    { mandatory_keys :: [SvcParamKey]
    }
    deriving (Eq, Ord)

instance Show SPV_Mandatory where
    show (SPV_Mandatory ks) = show ks

instance SPV SPV_Mandatory where
    toSvcParamValue (SPV_Mandatory ks) =
        toSPV $
            mapM_ (put16 . fromSvcParamKey) ks
    fromSvcParamValue = fromSPV $ \len -> do
        SPV_Mandatory <$> sGetMany "Mandatory" len (toSvcParamKey <$> get16)

spv_mandatory :: [SvcParamKey] -> SvcParamValue
spv_mandatory keys = toSvcParamValue $ SPV_Mandatory keys

----------------------------------------------------------------

newtype SPV_Port = SPV_Port
    { port_number :: PortNumber
    }
    deriving (Eq, Ord)

instance Show SPV_Port where
    show (SPV_Port p) = show p

instance SPV SPV_Port where
    toSvcParamValue (SPV_Port p) = toSPV $ put16 $ fromIntegral p
    fromSvcParamValue = fromSPV $ \_ -> SPV_Port . fromIntegral <$> get16

spv_port :: PortNumber -> SvcParamValue
spv_port p = toSvcParamValue $ SPV_Port p

----------------------------------------------------------------

newtype SPV_IPv4Hint = SPV_IPv4Hint
    { hint_ipv4s :: [IPv4]
    }
    deriving (Eq, Ord)

instance Show SPV_IPv4Hint where
    show (SPV_IPv4Hint is) = show is

instance SPV SPV_IPv4Hint where
    toSvcParamValue (SPV_IPv4Hint is) = toSPV $ do
        mapM_ (mapM_ putInt8 . fromIPv4) is
    fromSvcParamValue = fromSPV $ \len -> do
        SPV_IPv4Hint <$> sGetMany "IPv4Hint" len (toIPv4 <$> getNBytes 4)

spv_ipv4hint :: [IPv4] -> SvcParamValue
spv_ipv4hint is = toSvcParamValue $ SPV_IPv4Hint is

----------------------------------------------------------------

newtype SPV_IPv6Hint = SPV_IPv6Hint
    { hint_ipv6s :: [IPv6]
    }
    deriving (Eq, Ord)

instance Show SPV_IPv6Hint where
    show (SPV_IPv6Hint is) = show is

instance SPV SPV_IPv6Hint where
    toSvcParamValue (SPV_IPv6Hint is) = toSPV $ do
        mapM_ (mapM_ putInt8 . fromIPv6b) is
    fromSvcParamValue = fromSPV $ \len -> do
        SPV_IPv6Hint <$> sGetMany "IPv6Hint" len (toIPv6b <$> getNBytes 16)

spv_ipv6hint :: [IPv6] -> SvcParamValue
spv_ipv6hint is = toSvcParamValue $ SPV_IPv6Hint is

----------------------------------------------------------------

-- | Type for application level protocol negotiation.
type ALPN = ShortByteString

newtype SPV_ALPN = SPV_ALPN
    { alpn_names :: [ALPN]
    }
    deriving (Eq, Ord)

instance Show SPV_ALPN where
    show (SPV_ALPN as) = show $ map (C8.unpack . Short.fromShort) as

instance SPV SPV_ALPN where
    toSvcParamValue (SPV_ALPN as) = toSPV $ mapM_ alpn as
      where
        alpn bs = do
            putInt8 $ Short.length bs
            putShortByteString bs
    fromSvcParamValue = fromSPV $ \len -> do
        SPV_ALPN <$> sGetMany "ALPN" len alpn
      where
        alpn = do
            len <- getInt8
            getNShortByteString len

spv_alpn :: [ALPN] -> SvcParamValue
spv_alpn as = toSvcParamValue $ SPV_ALPN as

----------------------------------------------------------------

newtype SPV_Opaque = SPV_Opaque
    { opaque_value :: Opaque
    }
    deriving (Eq, Ord, Show)

instance SPV SPV_Opaque where
    toSvcParamValue (SPV_Opaque o) = SvcParamValue o
    fromSvcParamValue (SvcParamValue o) = Just $ SPV_Opaque o

spv_opaque :: Opaque -> SvcParamValue
spv_opaque as = toSvcParamValue $ SPV_Opaque as

----------------------------------------------------------------

newtype SPV_DoHPath = SPV_DoHPath
    { dohpath :: ShortByteString
    }
    deriving (Eq, Ord)

instance Show SPV_DoHPath where
    show (SPV_DoHPath p) = show $ C8.unpack $ Short.fromShort p

instance SPV SPV_DoHPath where
    toSvcParamValue (SPV_DoHPath p) = toSPV $ putShortByteString p
    fromSvcParamValue = fromSPV $ \len -> SPV_DoHPath <$> getNShortByteString len

spv_dohpath :: ShortByteString -> SvcParamValue
spv_dohpath as = toSvcParamValue $ SPV_DoHPath as
