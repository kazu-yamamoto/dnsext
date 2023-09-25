module DNS.SEC.Imports (
    ByteString,
    ShortByteString,
    NonEmpty (..),
    module Control.Applicative,
    module Control.Monad,
    module Data.Bits,
    module Data.Function,
    module Data.List,
    module Data.Maybe,
    module Data.Monoid,
    module Data.Ord,
    module Data.Typeable,
    module Data.Word,
    module Numeric,
    EpochTime,
    unconsLabels,
)
where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)
import Data.ByteString.Short (ShortByteString)
import Data.Function
import Data.List
import Data.List.NonEmpty (NonEmpty (..))
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.Typeable
import Data.Word
import Numeric

import DNS.Types (Domain, IsRepresentation (..))
import DNS.Types.Time (EpochTime)

unconsLabels :: Domain -> a -> (ShortByteString -> Domain -> a) -> a
unconsLabels = unconsLabels_

unconsLabels_ :: IsRepresentation a b => a -> c -> (b -> a -> c) -> c
unconsLabels_ rep nothing just = case toWireLabels rep of
    [] -> nothing
    x : xs -> just x $ fromWireLabels xs
