{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}

{-# OPTIONS -Wno-name-shadowing #-}

module DNS.Types.Base32Hex (
    encode,
    decode,
) where

import GHC.Exts (
    ByteArray#,
    Int (I#),
    MutableByteArray#,
    newByteArray#,
    unsafeFreezeByteArray#,
    writeWord8Array#,
 )
import GHC.ST (ST (ST), runST)
import GHC.Word (Word8 (W8#))

import qualified Data.Array.IArray as A
import qualified Data.Array.MArray as A
import qualified Data.Array.ST as A
import qualified Data.ByteString as BS
import Data.ByteString.Short.Internal (ShortByteString (SBS))

-- Don't import DNS.Types.Imports
import Control.Monad
import Data.Bits
import Data.ByteString (ByteString)
import Data.Word8 (_0, _9, _A, _V, _a, _v)

-- | Encode ByteString using the
-- <https://tools.ietf.org/html/rfc4648#section-7 RFC4648 base32hex>
-- encoding with no padding as specified for the
-- <https://tools.ietf.org/html/rfc5155#section-3.3 RFC5155 Next Hashed Owner Name>
-- field.
encode
    :: ByteString
    -- ^ input buffer
    -> ByteString
    -- ^ base32hex output
encode bs =
    let len = (8 * BS.length bs + 4) `div` 5
        ws = BS.unpack bs
     in BS.pack $ A.elems $ A.runSTUArray $ do
            a <- A.newArray (0 :: Int, len - 1) 0
            go ws a 0
  where
    toHex32 w
        | w < 10 = 48 + w
        | otherwise = 55 + w

    load8 a i = A.readArray a i
    store8 a i v = A.writeArray a i v

    -- Encode a list of 8-bit words at bit offset @n@
    -- into an array 'a' of 5-bit words.
    go [] a _ = A.mapArray toHex32 a
    go (w : ws) a n = do
        -- Split 8 bits into left, middle and right parts.  The
        -- right part only gets written when the 8-bit input word
        -- splits across three different 5-bit words.
        --
        let (q, r) = n `divMod` 5
            wl = w `shiftR` (3 + r)
            wm = (w `shiftL` (5 - r)) `shiftR` 3
            wr = (w `shiftL` (10 - r)) `shiftR` 3
        al <- case r of
            0 -> pure wl
            _ -> (wl .|.) <$> load8 a q
        store8 a q al
        store8 a (q + 1) wm
        when (r > 2) $ store8 a (q + 2) wr
        go ws a $ n + 8
{-# INLINE encode #-}

{- FOURMOLU_DISABLE -}
decode :: ByteString -> Either String ShortByteString
decode bs = do
    let ilen = BS.length bs
        len = (5 * ilen) `div` 8
        r = ilen `mod` 8
    unless (r `elem` [0, 2, 4, 5, 7]) $
        Left $ "Base32Hex.decode: invalid length of base32hex: " ++ show ilen
    runST $ do
        mba <- newByteArray len
        let finalize = do
                BA# ba# <- unsafeFreezeByteArray mba
                return $ Right $ SBS ba#
        loop (return . Left) finalize mba
  where
    fromHex32 w left right
        | _A <= w && w <= _V = right $ w - 55
        | _a <= w && w <= _v = right $ w - 87
        | _0 <= w && w <= _9 = right $ w - 48
        | otherwise = left "Base32Hex.decode: not base32hex format"

    store8 a i v = writeWord8Array a i v

    stores ss a n f0 f1 f2 f3 f4 f5 f6 f7 = do
        let w0 = f0 `unsafeShiftL` 3 .|. f1 `unsafeShiftR` 2
            w1 = f1 `unsafeShiftL` 6 .|. f2 `unsafeShiftL` 1 .|. f3 `unsafeShiftR` 4
            w2 = f3 `unsafeShiftL` 4 .|. f4 `unsafeShiftR` 1
            w3 = f4 `unsafeShiftL` 7 .|. f5 `unsafeShiftL` 2 .|. f6 `unsafeShiftR` 3
            w4 = f6 `unsafeShiftL` 5 .|. f7
            action
                | ss == (5 :: Int)  =
                               do { store8 a n w0 ; store8 a (n + 1) w1 ; store8 a (n + 2) w2 ; store8 a (n + 3) w3
                                  ; store8 a (n + 4) w4 }
                | ss ==  4   = do { store8 a n w0 ; store8 a (n + 1) w1 ; store8 a (n + 2) w2 ; store8 a (n + 3) w3 }
                | ss ==  3   = do { store8 a n w0 ; store8 a (n + 1) w1 ; store8 a (n + 2) w2 }
                | ss ==  2   = do { store8 a n w0 ; store8 a (n + 1) w1 }
                | ss ==  1   =      store8 a n w0
                | otherwise  = error "Base32Hex.decode: internal error. illegal chunk length"
        action

    bslen = BS.length bs
    loop left right a = go 0 0
      where
        fromH32 w = fromHex32 w left
        go n bsoff
            | r >= 8     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                  fromH32 b4 $ \f4 -> fromH32 b5 $ \f5 -> fromH32 b6 $ \f6 -> fromH32 b7 $ \f7 ->
                      do { stores 5 a n f0 f1 f2 f3 f4 f5 f6 f7 ; go (n + 5) (bsoff + 8) }
            | r == 7     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                  fromH32 b4 $ \f4 -> fromH32 b5 $ \f5 -> fromH32 b6 $ \f6 ->
                           stores 4 a n f0 f1 f2 f3 f4 f5 f6  0 *> right
            | r == 5     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                  fromH32 b4 $ \f4 ->
                           stores 3 a n f0 f1 f2 f3 f4  0  0  0 *> right
            | r == 4     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 -> fromH32 b2 $ \f2 -> fromH32 b3 $ \f3 ->
                           stores 2 a n f0 f1 f2 f3  0  0  0  0 *> right
            | r == 2     =
                  fromH32 b0 $ \f0 -> fromH32 b1 $ \f1 ->
                           stores 1 a n f0 f1  0  0  0  0  0  0 *> right
            | r == 0     = right
            | otherwise  = left $ "Base32Hex.decode: invalid input length: " ++ show bslen
          where
            r = bslen - bsoff
            ~b0 = bs `BS.index`  bsoff
            ~b1 = bs `BS.index` (bsoff + 1)
            ~b2 = bs `BS.index` (bsoff + 2)
            ~b3 = bs `BS.index` (bsoff + 3)
            ~b4 = bs `BS.index` (bsoff + 4)
            ~b5 = bs `BS.index` (bsoff + 5)
            ~b6 = bs `BS.index` (bsoff + 6)
            ~b7 = bs `BS.index` (bsoff + 7)

{-# INLINE decode #-}
{- FOURMOLU_ENABLE -}

-----

data BA = BA# ByteArray#
data MBA s = MBA# (MutableByteArray# s)

newByteArray :: Int -> ST s (MBA s)
newByteArray (I# len#) =
    ST $ \s -> case newByteArray# len# s of
        (# s, mba# #) -> (# s, MBA# mba# #)

unsafeFreezeByteArray :: MBA s -> ST s BA
unsafeFreezeByteArray (MBA# mba#) =
    ST $ \s -> case unsafeFreezeByteArray# mba# s of
        (# s, ba# #) -> (# s, BA# ba# #)

{-
readWord8Array :: MBA s -> Int -> ST s Word8
readWord8Array (MBA# mba#) (I# i#) =
    ST $ \s -> case readWord8Array# mba# i# s of
        (# s, w# #) -> (# s, W8# w# #)
 -}

writeWord8Array :: MBA s -> Int -> Word8 -> ST s ()
writeWord8Array (MBA# mba#) (I# i#) (W8# w#) =
    ST $ \s -> case writeWord8Array# mba# i# w# s of
        s -> (# s, () #)
