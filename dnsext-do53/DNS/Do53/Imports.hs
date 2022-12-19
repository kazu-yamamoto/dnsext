module DNS.Do53.Imports (
    ByteString
  , ShortByteString
  , Int64
  , module Control.Applicative
  , module Control.Monad
  , module Data.Bits
  , module Data.Function
  , module Data.List
  , module Data.Maybe
  , module Data.Monoid
  , module Data.Ord
  , module Data.Typeable
  , module Data.Word
  , module Numeric
  , EpochTime
  , getEpochTime
  ) where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)
import Data.Function
import Data.Int (Int64)
import Data.List hiding (lookup)
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.Typeable
import Data.Word
import Numeric

import Data.UnixTime (getUnixTime, UnixTime(..))
import Foreign.C.Types (CTime(..))

type EpochTime = Int64

getEpochTime :: IO Int64
getEpochTime = do
    UnixTime (CTime tim) _ <- getUnixTime
    return tim
