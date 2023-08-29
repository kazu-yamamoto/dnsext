{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Protocol buffer implementaion
--
-- Spec: https://protobuf.dev/programming-guides/encoding/
module DNS.TAP.ProtocolBuffer (
    -- * Types
    Object,
    -- * Decoding
    decode,
    getI,
    getOptI,
    getS,
    getOptS,
    -- * Encoding
    setI,
    setS,
) where

import Data.Bits
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IM
import Network.ByteOrder
import System.IO.Unsafe (unsafeDupablePerformIO)

----------------------------------------------------------------

-- assuming that Int is 64bit
data Value
    = VINT Int
    | VSTR ByteString
    deriving (Eq, Show)

-- | Object type for protocol buffer
newtype Object = Object (IntMap Value) deriving (Eq, Show)

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

-- | Getting a required integer field.
getI :: Object -> Int -> (Int -> a) -> a
getI (Object m) k f = case IM.lookup k m of
    Just (VINT i) -> f i
    _ -> error "getOptI"

-- | Getting a optional integer field.
getOptI :: Object -> Int -> (Int -> a) -> Maybe a
getOptI (Object m) k f = case IM.lookup k m of
    Just (VINT i) -> Just (f i)
    Just _ -> error "getOptI"
    _ -> Nothing

-- | Getting a required string field.
getS :: Object -> Int -> (ByteString -> a) -> a
getS (Object m) k f = case IM.lookup k m of
    Just (VSTR s) -> f s
    _ -> error "getS"

-- | Getting a optional string field.
getOptS :: Object -> Int -> (ByteString -> a) -> Maybe a
getOptS (Object m) k f = case IM.lookup k m of
    Just (VSTR s) -> Just (f s)
    Just _ -> error "getOptS"
    _ -> Nothing

----------------------------------------------------------------

-- | Setting an integer field.
setI :: Object -> Int -> Int -> Object
setI (Object m) k i = Object $ IM.insert k (VINT i) m

-- | Setting a string field.
setS :: Object -> Int -> ByteString -> Object
setS (Object m) k s = Object $ IM.insert k (VSTR s) m

----------------------------------------------------------------
-- Decoding
----------------------------------------------------------------

tag :: Readable p => p -> IO (Int, WireType)
tag rbuf = do
    n <- varint rbuf
    let wtyp = n .&. 0x7
        num = n `shiftR` 3
    return (num, WireType wtyp)

-- | Decoding
decode :: ByteString -> Object
decode bs = unsafeDupablePerformIO $
    withReadBuffer bs $
        \rbuf -> Object <$> loop rbuf IM.empty
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
    return
        ( (n7 `shiftL` 56)
            .|. (n6 `shiftL` 48)
            .|. (n5 `shiftL` 40)
            .|. (n4 `shiftL` 32)
            .|. (n3 `shiftL` 24)
            .|. (n2 `shiftL` 16)
            .|. (n1 `shiftL` 8)
            .|. n0
        )
