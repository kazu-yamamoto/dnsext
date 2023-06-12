module DNS.Types.Parser (
    Parser,
    Result (..),
    Builder,
    ToBuilder (..),
    parse,
    char,
    string,
    eof,
    option,
    match,
    skip,
    skipSome,
    satisfy,
    digit,
    anyChar,
) where

import DNS.Types.Imports
import DNS.Types.ShortBuilder
import DNS.Types.ShortParser hiding (char, string)
import qualified DNS.Types.ShortParser as P

parse
    :: Parser Builder
    -> ShortByteString
    -> (Maybe ShortByteString, ShortByteString)
parse p bs0 = case P.runParser p bs0 of
    (Unmatch, bs) -> (Nothing, bs)
    (Match b, bs) -> (Just (build b), bs)
    (Fail _, bs) -> (Nothing, bs)

char :: Word8 -> Parser Builder
char w = toBuilder <$> P.char w

string :: ShortByteString -> Parser Builder
string s = toBuilder <$> P.string s
