module DNS.Types.Base32Hex (
    encode
  , decode
  ) where

import qualified Data.Array.MArray as A
import qualified Data.Array.IArray as A
import qualified Data.Array.ST     as A
import qualified Data.ByteString   as BS

-- Don't import DNS.Types.Imports
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.List as L
import Data.Word8 (_0, _9, _A, _V, _a, _v)

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

decode :: ByteString -> Either String ByteString
decode bs = do
  let len = (5 * BS.length bs) `div` 8
  cs <- fmap chunks8 . mapM fromHex32 $ BS.unpack bs
  return $ BS.pack $ A.elems $ A.runSTUArray $ do
    a <- A.newArray (0 :: Int, len-1) 0
    go cs a 0
  where
    fromHex32 w
      | _0 <= w && w <= _9   =  Right $ w - 48
      | _A <= w && w <= _V   =  Right $ w - 55
      | _a <= w && w <= _v   =  Right $ w - 87
      | otherwise            =  Left "Base32Hex.decode: not base32hex format"

    chunks8 = L.unfoldr chunk
      where
        chunk s
          | null hd    =  Nothing
          | otherwise  =  Just (hd, tl)
          where (hd, tl) = splitAt 8 s

    store8 a i v = A.writeArray a i v

    stores ss a n f0 f1 f2 f3 f4 f5 f6 f7 = do
      let w0 = f0 `unsafeShiftL` 3 .|. f1 `unsafeShiftR` 2
          w1 = f1 `unsafeShiftL` 6 .|. f2 `unsafeShiftL` 1 .|. f3 `unsafeShiftR` 4
          w2 = f3 `unsafeShiftL` 4 .|. f4 `unsafeShiftR` 1
          w3 = f4 `unsafeShiftL` 7 .|. f5 `unsafeShiftL` 2 .|. f6 `unsafeShiftR` 3
          w4 = f6 `unsafeShiftL` 5 .|. f7
      sequence_ $
        take ss
        [ store8 a  n      w0,
          store8 a (n + 1) w1,
          store8 a (n + 2) w2,
          store8 a (n + 3) w3,
          store8 a (n + 4) w4 ]

    go [] a _n =  return a
    go ([f0,f1]:[]) a n = do
      stores 1 a n f0 f1 0 0 0 0 0 0
      -- let w0 = f0 `shiftL` 3 .|. f1 `shiftR` 2
      return a

    go ([f0,f1,f2,f3]:[]) a n = do
      stores 2 a n f0 f1 f2 f3 0 0 0 0
      -- let w0 = f0 `shiftL` 3 .|. f1 `shiftR` 2
      --     w1 = f1 `shiftL` 6 .|. f2 `shiftL` 1 .|. f3 `shiftR` 4
      return a

    go ([f0,f1,f2,f3,f4]:[]) a n = do
      stores 3 a n f0 f1 f2 f3 f4 0 0 0
      -- let w0 = f0 `shiftL` 3 .|. f1 `shiftR` 2
      --     w1 = f1 `shiftL` 6 .|. f2 `shiftL` 1 .|. f3 `shiftR` 4
      --     w2 = f3 `shiftL` 4 .|. f4 `shiftR` 1
      return a

    go ([f0,f1,f2,f3,f4,f5,f6]:[]) a n = do
      stores 4 a n f0 f1 f2 f3 f4 f5 f6 0
      -- let w0 = f0 `shiftL` 3 .|. f1 `shiftR` 2
      --     w1 = f1 `shiftL` 6 .|. f2 `shiftL` 1 .|. f3 `shiftR` 4
      --     w2 = f3 `shiftL` 4 .|. f4 `shiftR` 1
      --     w3 = f4 `shiftL` 7 .|. f5 `shiftL` 2 .|. f6 `shiftR` 3
      return a

    go ([f0,f1,f2,f3,f4,f5,f6,f7]:cs) a n = do
      stores 5 a n f0 f1 f2 f3 f4 f5 f6 f7
      -- let w0 = f0 `shiftL` 3 .|. f1 `shiftR` 2
      --     w1 = f1 `shiftL` 6 .|. f2 `shiftL` 1 .|. f3 `shiftR` 4
      --     w2 = f3 `shiftL` 4 .|. f4 `shiftR` 1
      --     w3 = f4 `shiftL` 7 .|. f5 `shiftL` 2 .|. f6 `shiftR` 3
      --     w4 = f6 `shiftL` 5 .|. f7
      go cs a (n + 5)

    go _ _ _ = error "Base32Hex.decode: internal error. invalid chunk"
{-# INLINE decode #-}
