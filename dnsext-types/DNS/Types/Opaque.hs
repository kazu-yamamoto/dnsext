module DNS.Types.Opaque (
    Opaque
  , null
  , singleton
  , concat
  , splitAt
  , uncons
  , length
  , foldr
  , toByteString
  , fromByteString
  , toShortByteString
  , fromShortByteString
  ) where

import Prelude hiding (null, concat, splitAt, length, foldr)

import DNS.Types.Opaque.Internal
