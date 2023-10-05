{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module DNS.Types.Seconds where

import DNS.StateBinary
import DNS.Types.Imports

newtype Seconds = Seconds Word32
    deriving (Eq, Ord, Enum, Num, Real, Integral, Bits)

instance Show Seconds where
    show (Seconds n) = show n ++ "(" ++ unit n ++ ")"
      where
        mul u k = if k == 1 then u else u ++ "s"
        unit i
            | i >= 86400 =
                let j = i `div` 86400
                 in show j ++ mul " day" j
            | i >= 3600 =
                let j = i `div` 3600
                 in show j ++ mul " hour" j
            | i >= 60 =
                let j = i `div` 60
                 in show j ++ mul " min" j
            | otherwise = mul "sec" i

putSeconds :: Seconds -> SPut ()
putSeconds (Seconds n) wbuf _ = put32 wbuf n

getSeconds :: SGet Seconds
getSeconds rbuf _ = Seconds <$> get32 rbuf
