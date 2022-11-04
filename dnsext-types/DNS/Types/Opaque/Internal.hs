module DNS.Types.Opaque.Internal where

import qualified Data.ByteString.Short as Short

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
showOpaque (Opaque o) = "\\# "
                     ++ show (Short.length o)
                     ++ " "
                     ++ b16encode (Short.fromShort o)

----------------------------------------------------------------

toByteString :: Opaque -> ByteString
toByteString (Opaque o) = Short.fromShort o

fromByteString :: ByteString -> Opaque
fromByteString = Opaque . Short.toShort

toShortByteString :: Opaque -> ShortByteString
toShortByteString (Opaque o) = o

fromShortByteString :: ShortByteString -> Opaque
fromShortByteString = Opaque

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
    (x,y) = Short.splitAt n sbs

uncons :: Opaque -> Maybe (Word8, Opaque)
uncons (Opaque sbs) = case Short.uncons sbs of
  Just (x,sbs') -> Just (x, Opaque sbs')
  Nothing       -> Nothing

length :: Opaque -> Int
length (Opaque sbs) = Short.length sbs

foldr :: (Word8 -> b -> b) -> b -> Opaque -> b
foldr f ini (Opaque sbs) = Short.foldr f ini sbs

----------------------------------------------------------------

putOpaque :: Opaque -> SPut
putOpaque (Opaque o) = putShortByteString o

getOpaque :: Int -> SGet Opaque
getOpaque len = Opaque <$> getNShortByteString len

putLenOpaque :: Opaque -> SPut
putLenOpaque (Opaque o) =
    -- put the length of the given string
    putInt8 (fromIntegral $ Short.length o)
 <> putShortByteString o

getLenOpaque :: SGet Opaque
getLenOpaque = Opaque <$> (getInt8 >>= getNShortByteString)
