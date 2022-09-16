module DNS.Types.Base32Hex (encode) where

import qualified Data.Array.MArray as A
import qualified Data.Array.IArray as A
import qualified Data.Array.ST     as A
import qualified Data.ByteString   as BS

-- Don't import DNS.Types.Imports
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)

-- | Encode ByteString using the
-- <https://tools.ietf.org/html/rfc4648#section-7 RFC4648 base32hex>
-- encoding with no padding as specified for the
-- <https://tools.ietf.org/html/rfc5155#section-3.3 RFC5155 Next Hashed Owner Name>
-- field.
--
encode :: ByteString -- ^ input buffer
       -> ByteString -- ^ base32hex output
encode bs =
    let len = (8 * BS.length bs + 4) `div` 5
        ws  = BS.unpack bs
     in BS.pack $ A.elems $ A.runSTUArray $ do
        a <- A.newArray (0 :: Int, len-1) 0
        go ws a 0
  where
    toHex32 w | w < 10    = 48 + w
              | otherwise = 55 + w

    load8  a i   = A.readArray  a i
    store8 a i v = A.writeArray a i v

    -- Encode a list of 8-bit words at bit offset @n@
    -- into an array 'a' of 5-bit words.
    go [] a _ = A.mapArray toHex32 a
    go (w:ws) a n = do
        -- Split 8 bits into left, middle and right parts.  The
        -- right part only gets written when the 8-bit input word
        -- splits across three different 5-bit words.
        --
        let (q, r) = n `divMod` 5
            wl =  w `shiftR` ( 3 + r)
            wm = (w `shiftL` ( 5 - r))  `shiftR` 3
            wr = (w `shiftL` (10 - r)) `shiftR` 3
        al <- case r of
              0 -> pure wl
              _ -> (wl .|.) <$> load8 a q
        store8 a q al
        store8 a (q + 1) wm
        when (r > 2) $ store8 a (q+2) wr
        go ws a $ n + 8
{-# INLINE encode #-}
