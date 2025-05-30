{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UnboxedTuples #-}
{-# LANGUAGE NoStrict #-}
{-# LANGUAGE NoStrictData #-}

module DNS.Array where

import Data.Array.Base (STUArray (..))
import Data.Array.IO.Internals (IOUArray (..))
import Data.Array.MArray (Ix (..))
import GHC.IO (IO (..))
import GHC.Exts (Int (..), atomicReadIntArray#, casIntArray#, (==#))

atomicModifyIntArray :: Ix ix => IOUArray ix Int -> ix -> (Int -> Int) -> IO Int
atomicModifyIntArray (IOUArray (STUArray l u _s mba)) ix f =
    atomicModify mba $ index (l, u) ix
  where
    -- stolen from "massiv"
    atomicModify mba# (I# i#) =
        let go s# o# =
                let !(I# n#) = f (I# o#)
                 in case casIntArray# mba# i# o# n# s# of
                        (# s'#, o'# #) ->
                            case o# ==# o'# of
                                0# -> go s# o'#
                                _ -> (# s'#, I# o# #)
         in IO $ \s# ->
                case atomicReadIntArray# mba# i# s# of
                    (# s'#, o# #) -> go s'# o#
    {-# INLINE atomicModify #-}
{-# INLINE atomicModifyIntArray #-}
