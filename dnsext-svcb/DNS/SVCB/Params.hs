module DNS.SVCB.Params where

import Data.IntMap (IntMap)
import qualified Data.IntMap as M

import DNS.SVCB.Imports
import DNS.SVCB.Key
import DNS.SVCB.Value

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
