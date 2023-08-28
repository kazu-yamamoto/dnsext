{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Protocol buffer implementaion
--
-- Spec: https://protobuf.dev/programming-guides/encoding/
module DNS.TAP.ProtocolBuffer
  (Object
  ,decode
  ,getI
  ,getIm
  ,getS
  ,getSm
  ) where

import Data.Bits
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as C8
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IM
import Network.ByteOrder

----------------------------------------------------------------

-- assuming that Int is 64bit
data Value = VINT Int
           | VSTR ByteString
           deriving (Eq, Show)

newtype Object = Object (IntMap Value) deriving (Eq, Show)

getIm :: Object -> Int -> (Int -> a) -> Maybe a
getIm (Object m) k f = case IM.lookup k m of
  Just (VINT i) -> Just (f i)
  Just _ -> error "getIm"
  _      -> Nothing

getI :: Object -> Int -> (Int -> a) -> a
getI (Object m) k f = case IM.lookup k m of
  Just (VINT i) -> f i
  _ -> error "getIm"

getSm :: Object -> Int -> (ByteString -> a) -> Maybe a
getSm (Object m) k f = case IM.lookup k m of
  Just (VSTR s) -> Just (f s)
  Just _ -> error "getIm"
  _      -> Nothing

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
          _   -> error "unknown wiretype"
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
i64 = undefined

----------------------------------------------------------------

skip :: Readable a1 => a1 -> WireType -> IO ()
skip rbuf VARINT = do
    len <- varint rbuf
    putStrLn $ "skipping VARINT " ++ show len
skip rbuf I64 = do
    _ <- read64 rbuf -- fixme endian
    putStrLn "skipping I64"
skip rbuf LEN = do
    len <- varint rbuf
    putStrLn $ "skipping LEN " ++ show len
    ff rbuf len
skip rbuf I32 = do
    _ <- i32 rbuf
    putStrLn "skipping I32"
skip rbuf _ = do
    putStrLn "skipping VARINT unknown"
    remainingSize rbuf >>= ff rbuf

dump :: Readable a => a -> IO ()
dump rbuf = do
    len <- varint rbuf
    bs <- extractByteString rbuf len
    C8.putStrLn $ B16.encode bs

dumpASCII :: Readable a => a -> IO ()
dumpASCII rbuf = do
    len <- varint rbuf
    extractByteString rbuf len >>= C8.putStrLn
