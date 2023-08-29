{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

-- | Protocol buffer implementaion
--
-- Spec: https://protobuf.dev/programming-guides/encoding/
--
-- This library assumes that 'Int' is 64bit.
-- VARINT, I32 and I64 is stored as 'Int' in an 'Object'.
-- LEN is stored as 'ByteString'.
module DNS.TAP.ProtocolBuffer (
    -- * Types
    Object,
    empty,
    FieldNumber,
    -- * Decoding
    decode,
    getI,
    getOptI,
    getS,
    getOptS,
    -- * Encoding
    encode,
    setVAR,
    setOptVAR,
    setI32,
    setOptI32,
    setI64,
    setOptI64,
    setS,
    setOptS,
) where

import Data.Bits
import qualified Data.ByteString as BS
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IM
import Network.ByteOrder
import System.IO.Unsafe (unsafeDupablePerformIO, unsafePerformIO)

----------------------------------------------------------------

-- assuming that Int is 64bit
data Value
    = VVAR Int
    | VI32 Int
    | VI64 Int
    | VSTR ByteString
    deriving (Eq, Show)

-- | Object type for protocol buffer
newtype Object = Object (IntMap Value) deriving (Eq, Show)

-- | Empty object.
empty :: Object
empty = Object IM.empty

-- | Field number.
type FieldNumber = Int

----------------------------------------------------------------

-- | Wire type.
newtype WireType = WireType { fromWireType :: Int } deriving (Eq)

pattern VAR :: WireType
pattern VAR  = WireType 0
pattern I64 :: WireType
pattern I64  = WireType 1
pattern LEN :: WireType
pattern LEN  = WireType 2
pattern I32 :: WireType
pattern I32  = WireType 5

instance Show WireType where
    show VAR          = "VARINT"
    show I64          = "I64"
    show LEN          = "LEN"
    show I32          = "I32"
    show (WireType x) = "WireType " ++ show x

----------------------------------------------------------------

-- | Getting a required integer (VARINT\/I32\/I64) field.
getI :: Object -> FieldNumber -> (Int -> a) -> a
getI (Object m) k f = case IM.lookup k m of
    Just (VVAR i) -> f i
    Just (VI32 i) -> f i
    Just (VI64 i) -> f i
    _ -> error "getOptI"

-- | Getting a optional integer (VARINT\/I32\/I64) field.
getOptI :: Object -> FieldNumber -> (Int -> a) -> Maybe a
getOptI (Object m) k f = case IM.lookup k m of
    Just (VVAR i) -> Just (f i)
    Just (VI32 i) -> Just (f i)
    Just (VI64 i) -> Just (f i)
    Just _ -> error "getOptI"
    _ -> Nothing

-- | Getting a required string (LEN) field.
getS :: Object -> FieldNumber -> (ByteString -> a) -> a
getS (Object m) k f = case IM.lookup k m of
    Just (VSTR s) -> f s
    _ -> error "getS"

-- | Getting a optional string (LEN) field.
getOptS :: Object -> FieldNumber -> (ByteString -> a) -> Maybe a
getOptS (Object m) k f = case IM.lookup k m of
    Just (VSTR s) -> Just (f s)
    Just _ -> error "getOptS"
    _ -> Nothing

----------------------------------------------------------------

-- | Setting a required integer (VARINT) field.
setVAR :: FieldNumber -> Int -> Object -> Object
setVAR k i (Object m) = Object $ IM.insert k (VVAR i) m

-- | Setting an optional integer (VARINT) field.
setOptVAR :: FieldNumber -> Maybe Int -> Object -> Object
setOptVAR k (Just i) (Object m) = Object $ IM.insert k (VVAR i) m
setOptVAR _ _ obj = obj

-- | Setting a required integer (I32) field.
setI32 :: FieldNumber -> Int -> Object -> Object
setI32 k i (Object m) = Object $ IM.insert k (VI32 i) m

-- | Setting an optional integer (I32) field.
setOptI32 :: FieldNumber -> Maybe Int -> Object -> Object
setOptI32 k (Just i) (Object m) = Object $ IM.insert k (VI32 i) m
setOptI32 _ _ obj = obj

-- | Setting a required integer (I64) field.
setI64 :: FieldNumber -> Int -> Object -> Object
setI64 k i (Object m) = Object $ IM.insert k (VI64 i) m

-- | Setting an required integer (I64) field.
setOptI64 :: FieldNumber -> Maybe Int -> Object -> Object
setOptI64 k (Just i) (Object m) = Object $ IM.insert k (VI64 i) m
setOptI64 _ _ obj = obj

-- | Setting a required string (LEN) field.
setS :: FieldNumber -> ByteString -> Object -> Object
setS k s (Object m) = Object $ IM.insert k (VSTR s) m

-- | Setting an optional string (LEN) field.
setOptS :: FieldNumber -> Maybe ByteString -> Object -> Object
setOptS k (Just s) (Object m) = Object $ IM.insert k (VSTR s) m
setOptS _ _ obj = obj

----------------------------------------------------------------
-- Decoding
----------------------------------------------------------------

-- | Decoding
decode :: ByteString -> Object
decode bs = unsafeDupablePerformIO $
    withReadBuffer bs $
        \rbuf -> Object <$> loop rbuf IM.empty
  where
    loop rbuf m0 = do
        (field, wt) <- decodeTag rbuf
        v <- case wt of
            VAR -> VVAR <$> decodeVarint rbuf
            I32 -> VI32 <$> decodeI32 rbuf
            LEN -> do
                lenPref <- decodeVarint rbuf
                VSTR <$> extractByteString rbuf lenPref
            I64 -> VI64 <$> decodeI64 rbuf
            _ -> error "unknown wiretype"
        let m = IM.insert field v m0
        rest <- remainingSize rbuf
        if rest == 0
            then return m
            else loop rbuf m

decodeTag :: Readable p => p -> IO (FieldNumber, WireType)
decodeTag rbuf = do
    n <- decodeVarint rbuf
    let wtyp = n .&. 0x7
        num = n `shiftR` 3
    return (num, WireType wtyp)

----------------------------------------------------------------

decodeVarint :: Readable p => p -> IO Int
decodeVarint rbuf = loop 0 0
  where
    loop n0 s = do
        n <- fromIntegral <$> read8 rbuf
        let n1 = n0 + ((n .&. 0x7f) `shiftL` s)
        if n `testBit` 7
            then loop n1 (s + 7)
            else return n1

decodeI32 :: Readable a => a -> IO Int
decodeI32 rbuf = do
    n0 <- fromIntegral <$> read8 rbuf
    n1 <- fromIntegral <$> read8 rbuf
    n2 <- fromIntegral <$> read8 rbuf
    n3 <- fromIntegral <$> read8 rbuf
    return ((n3 `shiftL` 24) .|. (n2 `shiftL` 16) .|. (n1 `shiftL` 8) .|. n0)

decodeI64 :: Readable a => a -> IO Int
decodeI64 rbuf = do
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

----------------------------------------------------------------
-- Encoding
----------------------------------------------------------------

-- | Encoding
encode :: Object -> ByteString
encode (Object m) = unsafePerformIO $
    withWriteBuffer len $ \wbuf -> loop wbuf lst
  where
    lst = IM.toAscList m
    len = sum $ map (\(_,v) -> vlen v) lst
    loop _ [] = return ()
    loop wbuf ((field,v):vs) = do
        encodeTag wbuf field $ vwt v
        case v of
          VVAR i -> encodeVarint wbuf i
          VI32 i -> encodeI32 wbuf i
          VI64 i -> encodeI64 wbuf i
          VSTR s -> do
              encodeVarint wbuf $ BS.length s
              copyByteString wbuf s
        loop wbuf vs

varintLength :: Int
varintLength = 4

tagLength :: Int
tagLength = varintLength

vlen :: Value -> Int
vlen (VVAR _)  = tagLength + varintLength
vlen (VI32 _)  = tagLength + 4
vlen (VI64 _)  = tagLength + 8
vlen (VSTR bs) = tagLength + varintLength + BS.length bs

vwt :: Value -> WireType
vwt (VVAR _) = VAR
vwt (VI32 _) = I32
vwt (VI64 _) = I64
vwt (VSTR _) = LEN


encodeTag :: WriteBuffer -> FieldNumber -> WireType -> IO ()
encodeTag wbuf field wt =
    encodeVarint wbuf ((field `shiftL` 3) .|. fromWireType wt)

----------------------------------------------------------------

encodeVarint :: WriteBuffer -> Int -> IO ()
encodeVarint wbuf n0 = loop n0
  where
    loop n | n < 128 = write8 wbuf $ fromIntegral n
    loop n = do
        write8 wbuf $ fromIntegral ((n .&. 0x7f) `setBit` 7)
        loop (n `shiftR` 7)

encodeI32 :: WriteBuffer -> Int -> IO ()
encodeI32 wbuf i = do
    write8 wbuf $ fromIntegral  (i              .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR`  8) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 16) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 24) .&. 0xff)

encodeI64 :: WriteBuffer -> Int -> IO ()
encodeI64 wbuf i = do
    write8 wbuf $ fromIntegral  (i              .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR`  8) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 16) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 24) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 32) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 40) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 48) .&. 0xff)
    write8 wbuf $ fromIntegral ((i `shiftR` 54) .&. 0xff)
