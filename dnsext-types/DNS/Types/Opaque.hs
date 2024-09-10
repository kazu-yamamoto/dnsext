module DNS.Types.Opaque (
    Opaque,
    null,
    singleton,
    concat,
    splitAt,
    uncons,
    length,
    foldr,
    toByteString,
    fromByteString,
    toShortByteString,
    fromShortByteString,
    toString,
    toBase16,
    fromBase16,
    toBase32Hex,
    fromBase32Hex,
    toBase64,
    fromBase64,
) where

import Prelude hiding (concat, foldr, length, null, splitAt)

import DNS.Types.Opaque.Internal
