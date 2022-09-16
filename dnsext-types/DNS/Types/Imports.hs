module DNS.Types.Imports (
    ByteString
  , ShortByteString
  , Text
  , Int64
  , NonEmpty(..)
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
  , b16encode
  , b32encode
  , b64encode
  ) where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8  as C8
import Data.ByteString.Short (ShortByteString)
import Data.Function
import Data.Int (Int64)
import Data.List
import Data.List.NonEmpty (NonEmpty(..))
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.Text (Text)
import Data.Typeable
import Data.Word
import Numeric

import qualified DNS.Types.Base32Hex as B32

b16encode, b32encode, b64encode :: ByteString -> String
b16encode = C8.unpack. B16.encode
b32encode = C8.unpack. B32.encode
b64encode = C8.unpack. B64.encode
