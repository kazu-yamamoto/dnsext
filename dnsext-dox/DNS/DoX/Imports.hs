module DNS.DoX.Imports (
    ByteString,
    ShortByteString,
    module Control.Applicative,
    module Control.Monad,
    module Data.Bits,
    module Data.Function,
    module Data.IP,
    module Data.List,
    module Data.Maybe,
    module Data.Monoid,
    module Data.Ord,
    module Data.String,
    module Data.Typeable,
    module Data.Word,
    module Numeric,
    toDNSError,
)
where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)
import Data.Function
import Data.IP
import Data.List
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.String
import Data.Typeable
import Data.Word
import Numeric

import qualified Control.Exception as E

import DNS.Types

toDNSError :: String -> IO a -> IO a
toDNSError tag action = action `E.catch` handler
  where
    handler se@(E.SomeException _) = E.throwIO $ NetworkFailure se tag
