{-# LANGUAGE NoStrict #-}

module DNS.ZoneFile.Lexer where

-- ghc packages
import Control.Applicative
import Control.Monad
import qualified Data.ByteString.Lazy as LB
import Data.Char (chr, ord)
import Numeric (readOct)

-- other packages
import Data.Word8

-- this package
import DNS.ZoneFile.Types hiding (Parser)
import qualified DNS.ZoneFile.Types as Poly

type Parser a = Poly.Parser Word8 LB.ByteString a

byte_token :: Parser Word8
byte_token = poly_token

byte :: Word8 -> Parser Word8
byte = this

bytes :: [Word8] -> Parser [Word8]
bytes = these

string :: String -> Parser [Word8]
string s = bytes $ map (fromIntegral . ord) s

---

-- RFC 1035 5.1 Format

-- $setup
-- >>> :seti -XOverloadedStrings
-- >>> import Data.String (fromString)
-- >>> import Data.Either (isLeft, isRight)
-- >>> import Text.Printf (printf)

isSpc :: Word8 -> Bool
isSpc = (||) <$> (== _tab) <*> (== _space)

isNewline :: Word8 -> Bool
isNewline = (||) <$> (== _cr) <*> (== _lf)

-- |
-- >>> runParser spc " abc"
-- Right ((),"abc")
-- >>> runParser spc "\tpqr"
-- Right ((),"pqr")
-- >>> isLeft $ runParser spc "abc"
-- True
spc :: Parser ()
spc = void $ satisfy "tab or space" isSpc

{- FOURMOLU_DISABLE -}
-- |
-- >>> runParser lineComment "; example"
-- Right ((),"")
-- >>> isLeft $ runParser lineComment "abc; example"
-- True
lineComment :: Parser ()
lineComment = void( byte _semicolon *> many not_nl )
  where not_nl = satisfy "not newline" $ not . isNewline

-- |
-- >>> runParser newline "\n"
-- Right ((),"")
-- >>> runParser newline "\r\n"
-- Right ((),"")
-- >>> runParser newline "\r"
-- Right ((),"")
newline :: Parser ()
newline =
    void
    ( byte _cr *> byte _lf  <|>
      byte _cr              <|>
      byte _lf )

-- | not escaped, not quoted, byte
-- >>> runParser cstringbSimple "abc"
-- Right (97,"bc")
-- >>> charset = "-+:" ++ ['0'..'9'] ++ ['A'..'Z'] ++ ['a'..'z']
-- >>> all isRight $ map (runParser (cstringbSimple <* eof) . fromString . (:"")) charset
-- True
-- >>> isLeft $ runParser cstringbSimple "."
-- True
-- >>> all isLeft $ map (runParser (cstringbSimple <* eof) . fromString . (:"")) ".;()\\\" \n"
-- True
cstringbSimple :: Parser Word8
cstringbSimple = satisfy "not (`.` || `;` || `\\` || `\"`) && not `space` && not `newline` && isPrint && isAscii" check
  where
    check c =
        c `notElem` [_period, _semicolon, _parenleft, _parenright, _backslash, _quotedbl] &&
        not (isSpc c) &&
        not (isNewline c) && isPrint c && isAscii c
{- FOURMOLU_ENABLE -}

backslash :: Parser ()
backslash = void $ byte _backslash

{- FOURMOLU_DISABLE -}
-- | backslash escaped byte
-- >>> runParser cstringbEscaped "\\abc"
-- Right (97,"bc")
-- >>> charset = " \t.\\\"" ++ "-+:" ++ ['A'..'Z'] ++ ['a'..'z']
-- >>> escaped c = fromString $ '\\':c:""
-- >>> all isRight $ map (runParser (cstringbEscaped <* eof) . escaped) charset
-- True
-- >>> isLeft $ runParser cstringbEscaped "\\\n"
-- True
cstringbEscaped :: Parser Word8
cstringbEscaped = backslash *> satisfy "not isDigit && not `newline` && isPrint && isAscii || tab" check
  where check c = not (isDigit c) && not (isNewline c) && isPrint c && isAscii c || c == _tab

-- | octal represented byte
-- >>> runParser cstringbOct "\\177"
-- Right (127,"")
-- >>> runParser cstringbOct "\\377"
-- Right (255,"")
-- >>> escapedOct i = fromString $ '\\' : printf "%03o" i
-- >>> octProp i = runParser cstringbOct (escapedOct i) == Right (i, "")
-- >>> all octProp [0..255]
-- True
cstringbOct :: Parser Word8
cstringbOct = backslash *> (replicateM 3 oct >>= getOct)
  where
    oct = satisfy "isOctDigit" isOctDigit
    getOct ws = case [ v | (v, "") <- readOct $ map (chr . fromIntegral) ws ] of
        []     -> raise ""
        v : _  -> pure v
-- |
-- >>> runParser cstringByte "zyx"
-- Right (122,"yx")
-- >>> runParser cstringByte "\\\t"
-- Right (9,"")
-- >>> runParser cstringByte "\\200"
-- Right (128,"")
cstringByte :: Parser Word8
cstringByte =
    cstringbSimple    <|>
    cstringbOct       <|>
    cstringbEscaped

quote :: Parser ()
quote = void $ byte _quotedbl

quotedByte :: Parser Word8
quotedByte =
    cstringbSimple    <|>
    cstringbOct       <|>
    cstringbEscaped   <|>
    satisfy "not (`\\` || `\"`) && not newline && isPrint || tab" check
  where
    check c =
        c `notElem` [_backslash, _quotedbl] &&
        not (isNewline c) && isPrint c && isAscii c
        || c == _tab
{- FOURMOLU_ENABLE -}

directive :: Parser Directive
directive = D_Origin <$ string "$ORIGIN" <|> D_TTL <$ string "$TTL"

{- FOURMOLU_DISABLE -}
-- |
--
-- >>> runParser lex_cstring "abc"
-- Right ("abc","")
-- >>> runParser lex_cstring "\"y.z\""
-- Right ("y.z","")
lex_cstring :: Parser CString
lex_cstring =
    cstringW8 <$>
    ( some cstringByte                  <|>
      quote *> many quotedByte <* quote )
{- FOURMOLU_ENABLE -}

comment :: Parser ()
comment = void (many spc *> lineComment *> optional newline)

{- FOURMOLU_DISABLE -}
token :: Parser Token
token =
    Directive <$> directive     <|>
    At <$ byte _at              <|>
    LParen <$ byte _parenleft   <|>
    RParen <$ byte _parenright  <|>
    Blank <$ some spc           <|>
    Dot <$ byte _period         <|>
    CS <$> lex_cstring          <|>
    Comment <$ comment
{- FOURMOLU_ENABLE -}

-- |
-- >>> lexLine "example.com. 7200 IN A 203.0.113.3  ; example record"
-- Right [CS "example",Dot,CS "com",Dot,Blank,CS "7200",Blank,CS "IN",Blank,CS "A",Blank,CS "203",Dot,CS "0",Dot,CS "113",Dot,CS "3",Blank,Comment]
lexLine :: LB.ByteString -> Either String [Token]
lexLine = (fst <$>) . runParser (many token <* eof)
