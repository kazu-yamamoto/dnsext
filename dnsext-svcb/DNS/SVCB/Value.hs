module DNS.SVCB.Value where

import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque
import Data.IP

import DNS.SVCB.Imports
import DNS.SVCB.Key

----------------------------------------------------------------

type SvcParamValue = Opaque

----------------------------------------------------------------

class SPV a where
    encodeSvcParamValue :: a -> Opaque
    decodeSvcParamValue :: Opaque -> Maybe a

encodeSPV :: SPut () -> Opaque
encodeSPV = Opaque.fromByteString . runSPut

decodeSPV :: (Int -> SGet a) -> Opaque -> Maybe a
decodeSPV parser o = case runSGet (parser len) bs of
    Right (r,_) -> Just r
    _           -> Nothing
  where
    bs = Opaque.toByteString o
    len = Opaque.length o

----------------------------------------------------------------

newtype SPV_Mandatory = SPV_Mandatory [SvcParamKey] deriving (Eq,Ord,Show)

instance SPV SPV_Mandatory where
    encodeSvcParamValue (SPV_Mandatory ks) = encodeSPV $
        mapM_ (put16 . fromSvcParamKey) ks
    decodeSvcParamValue = decodeSPV $ \len -> do
        SPV_Mandatory <$> sGetMany "Mandatory" len (toSvcParamKey <$> get16)

----------------------------------------------------------------

newtype SPV_Port = SPV_Port Word16 deriving (Eq,Ord,Show)

instance SPV SPV_Port where
    encodeSvcParamValue (SPV_Port p) = encodeSPV $ put16 p
    decodeSvcParamValue = decodeSPV $ \_ -> SPV_Port <$> get16

----------------------------------------------------------------

newtype SPV_IPv4Hint = SPV_IPv4Hint [IPv4] deriving (Eq,Ord,Show)

instance SPV SPV_IPv4Hint where
    encodeSvcParamValue (SPV_IPv4Hint is) = encodeSPV $ do
        mapM_ (mapM_ putInt8 . fromIPv4) is
    decodeSvcParamValue = decodeSPV $ \len -> do
        SPV_IPv4Hint <$> sGetMany "IPv4Hint" len (toIPv4 <$> getNBytes 4)

----------------------------------------------------------------

newtype SPV_IPv6Hint = SPV_IPv6Hint [IPv6] deriving (Eq,Ord,Show)

instance SPV SPV_IPv6Hint where
    encodeSvcParamValue (SPV_IPv6Hint is) = encodeSPV $ do
        mapM_ (mapM_ putInt8 . fromIPv6b) is
    decodeSvcParamValue = decodeSPV $ \len -> do
        SPV_IPv6Hint <$> sGetMany "IPv6Hint" len (toIPv6b <$> getNBytes 16)

----------------------------------------------------------------

newtype SPV_Opaque = SPV_Opaque Opaque deriving (Eq,Ord,Show)

instance SPV SPV_Opaque where
    encodeSvcParamValue (SPV_Opaque o) = o
    decodeSvcParamValue o = Just $ SPV_Opaque o
