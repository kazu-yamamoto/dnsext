{-# OPTIONS_GHC -Wno-orphans #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

-- | Parsers for Mighty
module Parser (
    -- * Utilities
    parseFile,
    parseString,
    parse,

    -- * Parsers
    Parser,
    spcs,
    spcs1,
    spc,
    commentLines,
    trailing,
    comment,
    eof,
    lookAhead,
    choice,
    digit,
    string,
    char,
    oneOf,
    noneOf,
) where

import Control.Applicative
import Control.Monad (void)
import qualified Data.ByteString.Lazy.Char8 as BL
import System.IO

import DNS.Parser hiding (Parser, eof, lookAhead, choice)
import qualified DNS.Parser as P

-- $setup
-- >>> {- workaround to avoid 'not in scope' errors: https://github.com/sol/doctest/issues/327#issuecomment-1405603806 -}
-- >>> :seti -XOverloadedStrings
-- >>> import Data.Either (isLeft)

type Parser = P.Parser BL.ByteString
type SourceName = FilePath

-- | Parsing a file.
--   If parsing fails, an 'IOException' is thrown.
parseFile :: Parser a -> FilePath -> IO a
parseFile p file = do
    hdl <- openFile file ReadMode
    hSetEncoding hdl latin1
    bs <- BL.hGetContents hdl
    parseLBS "parseFile" p bs

parseString :: Parser a -> String -> IO a
parseString p = parseLBS "parseString" p . BL.pack

parseLBS :: SourceName -> Parser a -> BL.ByteString -> IO a
parseLBS tag p bs =
    case parse p tag bs of
        Right x -> return x
        Left e -> fail e

parse :: Parser a -> SourceName -> BL.ByteString -> Either String a
parse p tag bs = either (\e -> Left $ tag ++ ": " ++ e) (Right . fst) $ runParser p bs

-- | 'Parser' to consume zero or more white spaces
--
-- >>> parse spcs "" "    "
-- Right ()
-- >>> parse spcs "" ""
-- Right ()
spcs :: Parser ()
spcs = void $ many spc

-- | 'Parser' to consume one or more white spaces
--
-- >>> parse spcs1 "" "    "
-- Right ()
-- >>> parse spcs1 "" " "
-- Right ()
-- >>> isLeft $ parse spcs1 "" ""
-- True
spcs1 :: Parser ()
spcs1 = void $ some spc

-- | 'Parser' to consume exactly one white space
--
-- >>> parse spc "" " "
-- Right ' '
-- >>> isLeft $ parse spc "" ""
-- True
spc :: Parser Char
spc = satisfyChar "spc" (`elem` " \t")

-- | 'Parser' to consume one or more comment lines
--
-- >>> parse commentLines "" "# comments\n# comments\n# comments\n"
-- Right ()
commentLines :: Parser ()
commentLines = void $ many commentLine
  where
    commentLine = trailing

-- | 'Parser' to consume a trailing comment
--
-- >>> parse trailing "" " \n"
-- Right ()
-- >>> parse trailing "" "# comments\n"
-- Right ()
-- >>> isLeft $ parse trailing "" "X# comments\n"
-- True
trailing :: Parser ()
trailing = void (spcs *> optional comment *> newline)

-- | 'Parser' to consume a trailing comment
--
-- >>> parse comment "" "# comments"
-- Right ()
-- >>> isLeft $ parse comment "" "foo"
-- True
comment :: Parser ()
comment = void $ char '#' <* many (noneOf "\n")

-----

eof :: Parser ()
eof = P.eof

lookAhead :: Parser a -> Parser a
lookAhead = P.lookAhead

choice :: [Parser a] -> Parser a
choice = P.choice

newline :: Parser Char
newline = satisfyChar "newline" (== '\n')

digit :: Parser Char
digit = satisfyChar "digit" (`elem` ['0'..'9'])

string :: String -> Parser String
string = mapM char

char :: Char -> Parser Char
char c = satisfyChar "char" (== c)

oneOf :: [Char] -> Parser Char
oneOf cs = satisfyChar "oneOf" (`elem` cs)

noneOf :: [Char] -> Parser Char
noneOf cs = satisfyChar "noneOf" (`notElem` cs)

satisfyChar :: String -> (Char -> Bool) -> Parser Char
satisfyChar name p = P.w8toChar <$> satisfy name (p . P.w8toChar)
