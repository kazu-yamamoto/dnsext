module DNS.Types.Opaque (
    Opaque
  , null
  , singleton
  , concat
  , splitAt
  , uncons
  , length
  , toByteString
  , fromByteString
  , toShortByteString
  , fromShortByteString
  ) where

import Prelude hiding (null, concat, splitAt, length)

import DNS.Types.Opaque.Internal
