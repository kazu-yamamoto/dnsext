{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Protocol buffer implementaion
--
-- Spec: https://protobuf.dev/programming-guides/encoding/
module DNS.TAP.ProtocolBuffer (
    Object,
    decode,
    getI,
    getIm,
    getS,
    getSm,
) where

import Data.Bits
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IM
import Network.ByteOrder

----------------------------------------------------------------

-- assuming that Int is 64bit
data Value
    = VINT Int
    | VSTR ByteString
    deriving (Eq, Show)

newtype Object = Object (IntMap Value) deriving (Eq, Show)

getIm :: Object -> Int -> (Int -> a) -> Maybe a
getIm (Object m) k f = case IM.lookup k m of
    Just (VINT i) -> Just (f i)
    Just _ -> error "getIm"
    _ -> Nothing

getI :: Object -> Int -> (Int -> a) -> a
getI (Object m) k f = case IM.lookup k m of
    Just (VINT i) -> f i
    _ -> error "getIm"

getSm :: Object -> Int -> (ByteString -> a) -> Maybe a
getSm (Object m) k f = case IM.lookup k m of
    Just (VSTR s) -> Just (f s)
    Just _ -> error "getIm"
    _ -> Nothing

getS :: Object -> Int -> (ByteString -> a) -> a
getS (Object m) k f = case IM.lookup k m of
    Just (VSTR s) -> f s
    _ -> error "getIm"

----------------------------------------------------------------

newtype WireType = WireType Int deriving (Eq)

pattern VARINT :: WireType
pattern VARINT = WireType 0
pattern I64 :: WireType
pattern I64 = WireType 1
pattern LEN :: WireType
pattern LEN = WireType 2
pattern I32 :: WireType
pattern I32 = WireType 5

instance Show WireType where
    show (WireType 0) = "VARINT"
    show (WireType 1) = "I64"
    show (WireType 2) = "LEN"
    show (WireType 5) = "I32"
    show (WireType x) = "WireType " ++ show x

----------------------------------------------------------------

tag :: Readable p => p -> IO (Int, WireType)
tag rbuf = do
    n <- varint rbuf
    let wtyp = n .&. 0x7
        num = n `shiftR` 3
    return (num, WireType wtyp)

decode :: ByteString -> IO Object
decode bs = do
    withReadBuffer bs $ \rbuf -> Object <$> loop rbuf IM.empty
  where
    loop rbuf m0 = do
        (field, wt) <- tag rbuf
        v <- case wt of
            VARINT -> VINT <$> varint rbuf
            I32 -> VINT <$> i32 rbuf
            LEN -> do
                lenPref <- varint rbuf
                VSTR <$> extractByteString rbuf lenPref
            I64 -> VINT <$> i64 rbuf
            _ -> error "unknown wiretype"
        let m = IM.insert field v m0
        rest <- remainingSize rbuf
        if rest == 0
            then return m
            else loop rbuf m

----------------------------------------------------------------

varint :: Readable p => p -> IO Int
varint rbuf = loop 0 0
  where
    loop n0 s = do
        n <- fromIntegral <$> read8 rbuf
        let n1 = n0 + ((n .&. 0x7f) `shiftL` s)
        if n `testBit` 7
            then loop n1 (s + 7)
            else return n1

i32 :: Readable a => a -> IO Int
i32 rbuf = do
    n0 <- fromIntegral <$> read8 rbuf
    n1 <- fromIntegral <$> read8 rbuf
    n2 <- fromIntegral <$> read8 rbuf
    n3 <- fromIntegral <$> read8 rbuf
    return ((n3 `shiftL` 24) .|. (n2 `shiftL` 16) .|. (n1 `shiftL` 8) .|. n0)

i64 :: Readable a => a -> IO Int
i64 rbuf = do
    n0 <- fromIntegral <$> read8 rbuf
    n1 <- fromIntegral <$> read8 rbuf
    n2 <- fromIntegral <$> read8 rbuf
    n3 <- fromIntegral <$> read8 rbuf
    n4 <- fromIntegral <$> read8 rbuf
    n5 <- fromIntegral <$> read8 rbuf
    n6 <- fromIntegral <$> read8 rbuf
    n7 <- fromIntegral <$> read8 rbuf
    return ((n7 `shiftL` 56) .|. (n6 `shiftL` 48) .|. (n5 `shiftL` 40) .|. (n4 `shiftL` 32) .|. (n3 `shiftL` 24) .|. (n2 `shiftL` 16) .|. (n1 `shiftL` 8) .|. n0)
