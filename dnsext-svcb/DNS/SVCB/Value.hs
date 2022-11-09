module DNS.SVCB.Value where

import DNS.Types
import DNS.Types.Internal
import qualified DNS.Types.Opaque as Opaque

import DNS.SVCB.Key

type SvcParamValue = Opaque

class SPV a where
    encodeSvcParamValue :: a -> Opaque
    decodeSvcParamValue :: Opaque -> Maybe a

newtype SPV_Mandatory = SPV_Moandatory [SvcParamKey] deriving (Eq,Ord,Show)

instance SPV SPV_Mandatory where
    encodeSvcParamValue (SPV_Moandatory ks) =
        Opaque.fromByteString $ runSPut $ mconcat sputs
          where
            sputs = put16 (fromSvcParamKey SPK_Mandatory)
                  : putInt16 (length ks * 2)
                  : map (put16 . fromSvcParamKey) ks
    decodeSvcParamValue o = case runSGet parser bs of
       Right (r,_) -> Just r
       _           -> Nothing
       where
         bs = Opaque.toByteString o
         parser = do
             len <- getInt16
             SPV_Moandatory <$> sGetMany "Mandatory" len (toSvcParamKey <$> get16)
