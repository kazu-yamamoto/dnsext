{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE UnboxedTuples #-}

module DNS.Types.ShortBuilder (
    ToBuilder(..)
  , Builder
  , build
  ) where

import qualified Data.ByteString.Short as Short
import Data.ByteString.Short.Internal (ShortByteString(..))
import GHC.Exts (Int(..), ByteArray#, MutableByteArray#, unsafeFreezeByteArray#, newByteArray#, writeWord8Array#, copyByteArray#)
import GHC.ST (ST(ST), runST)
import GHC.Word

import DNS.Types.Imports

data Piece = PWord8 Word8 | PShort ShortByteString

class ToBuilder a where
    toBuilder :: a -> Builder

instance ToBuilder Word8 where
    toBuilder w8 = Builder 1 ([PWord8 w8] ++)

instance ToBuilder ShortByteString where
    toBuilder sbs = Builder (Short.length sbs) ([PShort sbs] ++)

instance Semigroup Builder where
    Builder l0 b0 <> Builder l1 b1 = Builder (l0 + l1) (b0 . b1)

instance Monoid Builder where
    mempty = Builder 0 id

data Builder = Builder !Int ([Piece] -> [Piece])

build :: Builder -> ShortByteString
build (Builder len b) = create len $ \mba -> go mba 0 xs
  where
    xs = b []
    go _ _ [] = return ()
    go mba i (PWord8 w8 : cs) = do
        writeWord8Array mba i w8
        go mba (i+1) cs
    go mba i (PShort src : cs) = do
        let l = Short.length src
        copyByteArray (asBA src) 0 mba i l
        go mba (i+l) cs

-- Stolen from Data.ByteString.Short.Internal, sigh.

data BA    = BA# ByteArray#
data MBA s = MBA# (MutableByteArray# s)

create :: Int -> (forall s. MBA s -> ST s ()) -> ShortByteString
create len fill =
    runST (do
      mba <- newByteArray len
      fill mba
      BA# ba# <- unsafeFreezeByteArray mba
      return (SBS ba#))

newByteArray :: Int -> ST s (MBA s)
newByteArray (I# len#) =
    ST $ \s0 -> case newByteArray# len# s0 of
                 (# s, mba# #) -> (# s, MBA# mba# #)

unsafeFreezeByteArray :: MBA s -> ST s BA
unsafeFreezeByteArray (MBA# mba#) =
    ST $ \s0 -> case unsafeFreezeByteArray# mba# s0 of
                 (# s, ba# #) -> (# s, BA# ba# #)

writeWord8Array :: MBA s -> Int -> Word8 -> ST s ()
writeWord8Array (MBA# mba#) (I# i#) (W8# w#) =
  ST $ \s0 -> case writeWord8Array# mba# i# w# s0 of
               s -> (# s, () #)

copyByteArray :: BA -> Int -> MBA s -> Int -> Int -> ST s ()
copyByteArray (BA# src#) (I# src_off#) (MBA# dst#) (I# dst_off#) (I# len#) =
    ST $ \s0 -> case copyByteArray# src# src_off# dst# dst_off# len# s0 of
                 s -> (# s, () #)

asBA :: ShortByteString -> BA
asBA (SBS ba#) = BA# ba#
