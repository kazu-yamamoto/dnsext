module DNS.Types.Opaque.Internal where

import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short

import qualified DNS.Types.Base32Hex as B32H
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64

import DNS.StateBinary
import DNS.Types.Imports

----------------------------------------------------------------

-- | Opaque data.
newtype Opaque = Opaque ShortByteString deriving (Eq, Ord)

-- 8bit bytes. Don't use 'Text' since UTF8 uses the leftmost bit.

----------------------------------------------------------------

instance IsString Opaque where
    fromString = Opaque . fromString

instance Show Opaque where
    show = showOpaque

-- | RFC3597
showOpaque :: Opaque -> String
showOpaque (Opaque o) =
    "\\# "
        ++ show (Short.length o)
        ++ " "
        ++ C8.unpack (B16.encode $ Short.fromShort o)

----------------------------------------------------------------

toByteString :: Opaque -> ByteString
toByteString (Opaque o) = Short.fromShort o

fromByteString :: ByteString -> Opaque
fromByteString = Opaque . Short.toShort

toShortByteString :: Opaque -> ShortByteString
toShortByteString (Opaque o) = o

fromShortByteString :: ShortByteString -> Opaque
fromShortByteString = Opaque

toBase16 :: Opaque -> ByteString
toBase16 (Opaque o) = B16.encode $ Short.fromShort o

fromBase16 :: ByteString -> Either String Opaque
fromBase16 = (Opaque . Short.toShort <$>) . B16.decode

toBase32Hex :: Opaque -> ByteString
toBase32Hex (Opaque o) = B32H.encode $ Short.fromShort o

fromBase32Hex :: ByteString -> Either String Opaque
fromBase32Hex = (Opaque . Short.toShort <$>) . B32H.decode

toBase64 :: Opaque -> ByteString
toBase64 (Opaque o) = B64.encode $ Short.fromShort o

fromBase64 :: ByteString -> Either String Opaque
fromBase64 = (Opaque . Short.toShort <$>) . B64.decode

----------------------------------------------------------------

instance Semigroup Opaque where
    Opaque x <> Opaque y = Opaque (x <> y)

null :: Opaque -> Bool
null (Opaque sbs) = Short.null sbs

singleton :: Word8 -> Opaque
singleton w = Opaque $ Short.singleton w

concat :: [Opaque] -> Opaque
concat ss = Opaque $ Short.concat $ map toShortByteString ss

splitAt :: Int -> Opaque -> (Opaque, Opaque)
splitAt n (Opaque sbs) = (Opaque x, Opaque y)
  where
    (x, y) = Short.splitAt n sbs

uncons :: Opaque -> Maybe (Word8, Opaque)
uncons (Opaque sbs) = case Short.uncons sbs of
    Just (x, sbs') -> Just (x, Opaque sbs')
    Nothing -> Nothing

length :: Opaque -> Int
length (Opaque sbs) = Short.length sbs

foldr :: (Word8 -> b -> b) -> b -> Opaque -> b
foldr f ini (Opaque sbs) = Short.foldr f ini sbs

----------------------------------------------------------------

putOpaque :: Opaque -> SPut ()
putOpaque (Opaque o) wbuf _ = putShortByteString wbuf o

getOpaque :: Int -> SGet Opaque
getOpaque len rbuf _ = Opaque <$> getNShortByteString rbuf len

putLenOpaque :: Opaque -> SPut ()
putLenOpaque (Opaque o) wbuf _ = putLenShortByteString wbuf o

getLenOpaque :: SGet Opaque
getLenOpaque rbuf _ = Opaque <$> (getInt8 rbuf >>= getNShortByteString rbuf)
