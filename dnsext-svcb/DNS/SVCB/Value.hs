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
import Network.TLS.ECH.Config

----------------------------------------------------------------

newtype SvcParamValue = SvcParamValue Opaque deriving (Show, Eq, Ord)

----------------------------------------------------------------

class SPV a where
    fromSvcParamValue :: SvcParamValue -> Maybe a
    toSvcParamValue :: a -> SvcParamValue

toSPV :: Int -> Builder () -> SvcParamValue
toSPV siz = SvcParamValue . Opaque.fromByteString . runBuilder siz

fromSPV :: (Int -> Parser a) -> SvcParamValue -> Maybe a
fromSPV parser (SvcParamValue o) = case runParser (parser len) bs of
    Right r -> Just r
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
        toSPV siz $ \wbuf _ -> mapM_ (put16 wbuf . fromSvcParamKey) ks
      where
        siz = length ks * 2
    fromSvcParamValue = fromSPV $ \len rbuf ref -> do
        SPV_Mandatory <$> sGetMany "Mandatory" len (\_ _ -> toSvcParamKey <$> get16 rbuf) rbuf ref

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
    toSvcParamValue (SPV_Port p) = toSPV 2 $ \wbuf _ -> put16 wbuf $ fromIntegral p
    fromSvcParamValue = fromSPV $ \_ rbuf _ -> SPV_Port . fromIntegral <$> get16 rbuf

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
    toSvcParamValue (SPV_IPv4Hint is) = toSPV siz $ \wbuf _ -> do
        mapM_ (mapM_ (putInt8 wbuf) . fromIPv4) is
      where
        siz = length is * 4
    fromSvcParamValue = fromSPV $ \len rbuf ref -> do
        SPV_IPv4Hint <$> sGetMany "IPv4Hint" len ipv4hint rbuf ref
      where
        ipv4hint rbuf _ = toIPv4 <$> getNBytes rbuf 4

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
    toSvcParamValue (SPV_IPv6Hint is) = toSPV siz $ \wbuf _ -> do
        mapM_ (mapM_ (putInt8 wbuf) . fromIPv6b) is
      where
        siz = length is * 16
    fromSvcParamValue = fromSPV $ \len rbuf ref -> do
        SPV_IPv6Hint <$> sGetMany "IPv6Hint" len ipv6hint rbuf ref
      where
        ipv6hint rbuf _ = toIPv6b <$> getNBytes rbuf 16

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
    toSvcParamValue (SPV_ALPN as) = toSPV siz $ \wbuf _ -> mapM_ (alpn wbuf) as
      where
        siz = sum $ map (\s -> 1 + Short.length s) as
        alpn wbuf bs = do
            putInt8 wbuf $ Short.length bs
            putShortByteString wbuf bs
    fromSvcParamValue = fromSPV $ \len rbuf ref -> do
        SPV_ALPN <$> sGetMany "ALPN" len alpn rbuf ref
      where
        alpn rbuf _ = do
            len <- getInt8 rbuf
            getNShortByteString rbuf len

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
    toSvcParamValue (SPV_DoHPath p) = toSPV siz $ \wbuf _ -> putShortByteString wbuf p
      where
        siz = Short.length p
    fromSvcParamValue = fromSPV $ \len rbuf _ -> SPV_DoHPath <$> getNShortByteString rbuf len

spv_dohpath :: ShortByteString -> SvcParamValue
spv_dohpath as = toSvcParamValue $ SPV_DoHPath as

----------------------------------------------------------------

newtype SPV_ECH = SPV_ECH
    { ech_configs :: [ECHConfig]
    }
    deriving (Eq, Ord, Show)

instance SPV SPV_ECH where
    toSvcParamValue (SPV_ECH echcs) = toSPV siz $ \wbuf _ -> do
        put16 wbuf $ fromIntegral siz
        mapM_ (putECHConfig wbuf) echcs
      where
        siz = sum $ map sizeOfECHConfig echcs

    fromSvcParamValue = fromSPV $ \_len rbuf ref -> do
        len <- fromIntegral <$> get16 rbuf
        SPV_ECH <$> sGetMany "ECH" len (\_ _ -> getECHConfig rbuf) rbuf ref

spv_ech :: [ECHConfig] -> SvcParamValue
spv_ech cs = toSvcParamValue $ SPV_ECH cs
