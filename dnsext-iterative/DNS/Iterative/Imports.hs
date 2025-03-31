{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -Wno-dodgy-imports #-}

module DNS.Iterative.Imports (
    ByteString,
    module Control.Applicative,
    module Control.Arrow,
    module Control.Monad,
    module Control.Monad.IO.Class,
    module Control.Monad.Trans.Class,
    module Control.Monad.Trans.Except,
    module Control.Monad.Trans.Reader,
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
import Control.Monad.IO.Class
import Control.Monad.Trans.Class
import Control.Monad.Trans.Except hiding (liftCallCC)
import Control.Monad.Trans.Reader
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
