module DNS.Types.Parser (
    Parser
  , Builder
  , ToBuilder(..)
  , parse
  , char
  , string
  , eof
  , option
  , match
  , skip
  , skipSome
  , satisfy
  , digit
  , anyChar
  ) where

import DNS.Types.Imports
import DNS.Types.ShortBuilder
import qualified DNS.Types.ShortParser as P
import DNS.Types.ShortParser hiding (parse, char, string)

parse :: Parser Builder
      -> ShortByteString
      -> (Maybe ShortByteString, ShortByteString)
parse p bs0 = case P.parse p bs0 of
  (Nothing, bs) -> (Nothing, bs)
  (Just b,  bs) -> (Just (build b), bs)

char :: Word8 -> Parser Builder
char w = toBuilder <$> P.char w

string :: ShortByteString -> Parser Builder
string s = toBuilder <$> P.string s
