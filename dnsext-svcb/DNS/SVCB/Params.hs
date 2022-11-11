module DNS.SVCB.Params where

import DNS.Types
import Data.IntMap (IntMap)
import qualified Data.IntMap as M

import DNS.SVCB.Imports
import DNS.SVCB.Key
import DNS.SVCB.Value

newtype SvcParams = SvcParams (IntMap SvcParamValue) deriving (Eq, Ord)

instance Show SvcParams where
    show (SvcParams m) = "[" ++ intercalate ", " (M.foldrWithKey f [] m) ++ "]"
      where
        showkv k v = show (toSvcParamKey $ fromIntegral k) ++ "=" ++ showValue (toSvcParamKey $ fromIntegral k) v
        f k v xs = showkv k v : xs

showValue :: SvcParamKey -> Opaque -> String
showValue SPK_Port v = case decodeSvcParamValue v of
  Nothing -> ""
  Just x@(SPV_Port _) -> show x
showValue SPK_IPv4Hint v = case decodeSvcParamValue v of
  Nothing -> ""
  Just x@(SPV_IPv4Hint _) -> show x
showValue SPK_IPv6Hint v = case decodeSvcParamValue v of
  Nothing -> ""
  Just x@(SPV_IPv6Hint _) -> show x
showValue SPK_ALPN v = case decodeSvcParamValue v of
  Nothing -> ""
  Just x@(SPV_ALPN _) -> show x
showValue _ v = show v

lookupSvcParams :: SvcParamKey -> SvcParams -> Maybe SvcParamValue
lookupSvcParams key (SvcParams m) = M.lookup k m
  where
    k = fromIntegral $ fromSvcParamKey key

newSvcParams :: [(Int,SvcParamValue)] -> SvcParams
newSvcParams kvs = SvcParams $ foldr ins M.empty kvs
  where
    ins (k,v) = M.insert k v
