-- | Parsers for Mighty
module Parser (
    -- * Utilities
    parseFile,

    -- * Parsers
    spcs,
    spcs1,
    spc,
    commentLines,
    trailing,
    comment,
) where

import Control.Exception
import Control.Monad (void)
import qualified Data.ByteString.Lazy.Char8 as BL
import System.IO
import Text.Parsec
import Text.Parsec.ByteString.Lazy

-- $setup
-- >>> {- workaround to avoid 'not in scope' errors: https://github.com/sol/doctest/issues/327#issuecomment-1405603806 -}
-- >>> :seti -XOverloadedStrings
-- >>> import Data.Either (isLeft)

-- | Parsing a file.
--   If parsing fails, an 'IOException' is thrown.
parseFile :: Parser a -> FilePath -> IO a
parseFile p file = do
    hdl <- openFile file ReadMode
    hSetEncoding hdl latin1
    bs <- BL.hGetContents hdl
    case parse p "parseFile" bs of
        Right x -> return x
        Left e -> throwIO . userError . show $ e

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
spcs1 = void $ many1 spc

-- | 'Parser' to consume exactly one white space
--
-- >>> parse spc "" " "
-- Right ' '
-- >>> isLeft $ parse spc "" ""
-- True
spc :: Parser Char
spc = satisfy (`elem` " \t")

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
-- >>> parse trailing "" "# comments\n"
-- Right ()
-- >>> isLeft $ parse trailing "" "X# comments\n"
-- True
trailing :: Parser ()
trailing = void (spcs *> comment *> newline <|> spcs *> newline)

-- | 'Parser' to consume a trailing comment
--
-- >>> parse comment "" "# comments"
-- Right ()
-- >>> isLeft $ parse comment "" "foo"
-- True
comment :: Parser ()
comment = void $ char '#' <* many (noneOf "\n")
