{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -Wno-dodgy-imports #-}

module DNS.Iterative.Imports (
    ByteString,
    module Control.Applicative,
    module Control.Arrow,
    module Control.Monad,
    module Control.Monad.Trans,
    module Control.Monad.Except,
    module Control.Monad.Reader,
    module Data.Bits,
    module Data.Bool,
    module Data.Function,
    module Data.Functor,
    module Data.List,
    module Data.List.NonEmpty,
    module Data.Maybe,
    module Data.Monoid,
    module Data.Ord,
    module Data.String,
    module Data.Typeable,
    module Data.Word,
    module Numeric,
    module DNS.Types.Time,
    unzipNE,
)
where

-- GHC packages
import Control.Applicative
import Control.Arrow (first, second, (&&&), (***), (<<<), (>>>))
import Control.Monad
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Trans
import Data.Bits
import Data.Bool (bool)
import Data.ByteString (ByteString)
import Data.Function
import Data.Functor hiding (unzip)
import Data.List
import Data.List.NonEmpty (NonEmpty (..), nonEmpty)
import Data.Maybe
import Data.Monoid
import Data.Ord
import Data.String
import Data.Typeable
import Data.Word
import Numeric

-- dns packages
import DNS.Types.Time (EpochTime, EpochTimeUsec)

#if __GLASGOW_HASKELL__ >= 910
import qualified Data.Functor as F

unzipNE :: NonEmpty (a, b) -> (NonEmpty a, NonEmpty b)
unzipNE = F.unzip
#else
import qualified Data.List.NonEmpty as NE

unzipNE :: NonEmpty (a, b) -> (NonEmpty a, NonEmpty b)
unzipNE = NE.unzip
#endif
