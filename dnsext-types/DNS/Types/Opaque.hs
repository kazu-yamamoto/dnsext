module DNS.Types.Opaque (
    Opaque
  , opaqueToByteString
  , byteStringToOpaque
  , opaqueToShortByteString
  , shortByteStringToOpaque
  , putOpaque
  , getOpaque
  , putLenOpaque
  , getLenOpaque
  ) where

import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as Short
import Data.String

import DNS.StateBinary
import DNS.Types.Imports

----------------------------------------------------------------

-- | Opaque data.
newtype Opaque = Opaque ShortByteString deriving (Eq, Ord)
-- 8bit bytes. Don't use 'Text' since UTF8 uses the leftmost bit.

----------------------------------------------------------------

instance IsString Opaque where
    fromString = Opaque . Short.toShort . C8.pack

instance Show Opaque where
    show = showOpaque

-- | RFC3597
showOpaque :: Opaque -> String
showOpaque (Opaque o) = "\\# "
                     ++ show (Short.length o)
                     ++ " "
                     ++ b16encode (Short.fromShort o)

----------------------------------------------------------------

opaqueToByteString :: Opaque -> ByteString
opaqueToByteString (Opaque o) = Short.fromShort o

byteStringToOpaque :: ByteString -> Opaque
byteStringToOpaque = Opaque . Short.toShort

opaqueToShortByteString :: Opaque -> ShortByteString
opaqueToShortByteString (Opaque o) = o

shortByteStringToOpaque :: ShortByteString -> Opaque
shortByteStringToOpaque = Opaque

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
