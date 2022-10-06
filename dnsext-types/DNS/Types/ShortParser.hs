{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module DNS.Types.ShortParser where

import Control.Applicative
import Control.Monad
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.Word
import Data.Word8

----------------------------------------------------------------

newtype Parser a = Parser {
  -- | Getting the internal parser.
    runParser :: ShortByteString -> (Result a, ShortByteString)
  }

data Result a = Match a
              | Unmatch
              | Fail String
              deriving (Eq, Show)

----------------------------------------------------------------

instance Functor Parser where
    f `fmap` p = return f <*> p

instance Applicative Parser where
    pure a = Parser (Match a, )
    (<*>)  = ap

instance Monad Parser where
    return   = pure
    p >>= f  = Parser $ \bs -> case runParser p bs of
        (Unmatch, bs') -> (Unmatch, bs')
        (Match a, bs') -> runParser (f a) bs'
        (Fail s,  bs') -> (Fail s, bs')

instance MonadFail Parser where
    fail s = Parser (Fail s, )

-- no 'try'
instance MonadPlus Parser where
    mzero       = Parser (Unmatch, )
    p `mplus` q = Parser $ \bs -> case runParser p bs of
        (Unmatch, _)    -> runParser q bs
        (Match a,  bs') -> (Match a, bs')
        (Fail s,   bs') -> (Fail s,  bs')

instance Alternative Parser where
    empty = mzero
    (<|>) = mplus

----------------------------------------------------------------
-- | The parser @satisfy f@ succeeds for any character for which the
--   supplied function @f@ returns 'True'. Returns the character that is
--   actually parsed.
satisfy :: (Word8 -> Bool) -> Parser Word8
satisfy predicate = Parser sat
  where
    sat bs = case Short.uncons bs of
      Nothing         -> (Unmatch, "")
      Just (b,bs')
        | predicate b -> (Match b, bs')
        | otherwise   -> (Unmatch, bs)

eof :: Parser ()
eof = Parser $ \bs -> if bs == "" then (Match (), "") else (Unmatch, bs)

----------------------------------------------------------------

-- | @char c@ parses a single character @c@. Returns the parsed character.
char :: Word8 -> Parser Word8
char c = satisfy (c ==)

skip :: (Word8 -> Bool) -> Parser ()
skip = void . satisfy

-- | @string s@ parses a sequence of characters given by @s@. Returns
--   the parsed string

string :: ShortByteString -> Parser ShortByteString
string bs0 = loop bs0 >> pure bs0
 where
     loop bs = case Short.uncons bs of
       Nothing      -> pure ()
       Just (b,bs') -> do
           void $ char b
           void $ string bs'

----------------------------------------------------------------

-- | This parser succeeds for any character. Returns the parsed character.
anyChar :: Parser Word8
anyChar = satisfy (const True)

-- | @oneOf cs@ succeeds if the current character is in the supplied list of
--   characters @cs@. Returns the parsed character.
oneOf :: [Word8] -> Parser Word8
oneOf cs = satisfy (`elem` cs)

-- | As the dual of 'oneOf', @noneOf cs@ succeeds if the current
--   character /not/ in the supplied list of characters @cs@. Returns the
--   parsed character.
noneOf :: [Word8] -> Parser Word8
noneOf cs = satisfy (`notElem` cs)

-- | Parses a letter or digit (a character between \'0\' and \'9\').
--   Returns the parsed character.
alphaNum :: Parser Word8
alphaNum = satisfy isAlphaNum

-- | Parses a digit. Returns the parsed character.
digit :: Parser Word8
digit = satisfy isDigit

-- | Parses a hexadecimal digit (a digit or a letter between \'a\' and
--   \'f\' or \'A\' and \'F\'). Returns the parsed character.
hexDigit :: Parser Word8
hexDigit = satisfy isHexDigit

-- | Parses a white space character (any character which satisfies 'isSpace')
--   Returns the parsed character.
space :: Parser Word8
space = satisfy isSpace

----------------------------------------------------------------

-- | @choice ps@ tries to apply the parsers in the list @ps@ in order,
--   until one of them succeeds. Returns the value of the succeeding
--   parser.
choice :: [Parser a] -> Parser a
choice = foldr (<|>) mzero

-- | @option x p@ tries to apply parser @p@. If @p@ fails without
--   consuming input, it returns the value @x@, otherwise the value
--   returned by @p@.
option :: a -> Parser a -> Parser a
option x p = p <|> pure x

-- | @skipMany p@ applies the parser @p@ /zero/ or more times, skipping
--   its result.
skipMany :: Parser a -> Parser ()
skipMany p = void $ many p

-- | @skipSome p@ applies the parser @p@ /one/ or more times, skipping
--   its result.
skipSome :: Parser a -> Parser ()
skipSome p = void $ some p

-- | @sepBy1 p sep@ parses /one/ or more occurrences of @p@, separated
--   by @sep@. Returns a list of values returned by @p@.
sepBy1 :: Parser a -> Parser b -> Parser [a]
sepBy1 p sep = (:) <$> p <*> many (sep *> p)

-- | @manyTill p end@ applies parser @p@ /zero/ or more times until
--   parser @end@ succeeds. Returns the list of values returned by @p@.
manyTill :: Parser a -> Parser b -> Parser [a]
manyTill p end = scan
  where
    scan = [] <$ end <|> (:) <$> p <*> scan

match :: Parser a -> Parser (ShortByteString, a)
match p = Parser $ \bs -> case runParser p bs of
  (Unmatch, _)   -> (Unmatch, bs)
  (Match a, bs') -> let len  = Short.length bs
                        len' = Short.length bs'
                        bs'' = Short.take (len - len') bs
                    in (Match (bs'', a),  bs')
  (Fail s, _)    -> (Fail s, bs)
