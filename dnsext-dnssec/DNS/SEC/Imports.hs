{-# LANGUAGE OverloadedStrings #-}

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
    numLabels,
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

import DNS.Types (Domain, labelsCount, unconsDomain)
import DNS.Types.Internal (Label)
import DNS.Types.Time (EpochTime)

unconsLabels :: Domain -> a -> (Label -> Domain -> a) -> a
unconsLabels d nothing just = case unconsDomain d of
    Nothing -> nothing
    Just (x, xs) -> just x $ xs

{- FOURMOLU_DISABLE -}
numLabels :: Domain -> Int
numLabels d = unconsLabels d 0 nlabels
  where
    nlabels "*" _ = c - 1
    nlabels _   _ = c
    c = labelsCount d
{- FOURMOLU_ENABLE -}
