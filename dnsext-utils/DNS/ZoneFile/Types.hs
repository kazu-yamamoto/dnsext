
module DNS.ZoneFile.Types where

-- ghc packages
import qualified Data.ByteString.Short as Short
import Data.Char (chr)
import Data.List (unfoldr)
import Data.Word (Word8)

-- dnsext-* packages
import DNS.Types

-- this package
import DNS.Parser

raise :: MonadParser t s m => String -> m a
raise = parseError

poly_token :: CaseCons t s => Parser s t
poly_token = token

---

data Directive
    = D_Origin
    | D_TTL
    deriving (Eq, Show)

-- character-string or longer opaque-string
type CString = Short.ShortByteString

cstringW8 :: [Word8] -> CString
cstringW8 = Short.pack

fromCString :: CString -> String
fromCString = map (chr . fromIntegral) . Short.unpack

data Token
    = Directive Directive
    | At
    | LParen
    | RParen
    | Blank
    | Dot
    | CS CString
    | Comment
    | RSep
    deriving (Eq, Show)

instance ParserToken Token

---

type Line = [Token]

-- $setup
-- >>> :seti -XOverloadedStrings

{- FOURMOLU_DISABLE -}
-- |
-- >>> reduceParens1 [[CS "a",LParen,CS "b"], [CS "c",RParen,CS "d",LParen,CS "e"], [CS "f",RParen,CS "g"], [CS "h"]]
-- Just ([CS "a",LParen,CS "b",CS "c",RParen,CS "d",LParen,CS "e",CS "f",RParen,CS "g"],[[CS "h"]])
reduceParens1 :: [Line] -> Maybe (Line, [Line])
reduceParens1 [] = Nothing
reduceParens1 (ts0:xs0) = Just $ scan id ts0 xs0
  where
    scan a  []         xs  = (a [], xs)
    scan a (LParen:ts) xs  = inner (a . (LParen :)) ts xs
    scan a (t:ts)      xs  = scan (a . (t :)) ts xs

    inner a  []          []     = (a [], [])  {- mismatch case. missing last RParen -}
    inner a  []         (x:xs)  = inner a x xs
    inner a (RParen:ts)  xs     = scan (a . (RParen :)) ts xs
    inner a (t:ts) xs           = inner (a . (t :)) ts xs
{- FOURMOLU_ENABLE -}

reduceParens :: [Line] -> [Line]
reduceParens = unfoldr reduceParens1

{- FOURMOLU_DISABLE -}
-- |
-- >>> normLine [CS "example",Dot,CS "com",Dot,Blank,CS "7200",Blank,LParen,CS "IN",Blank,CS "A",Blank,CS "203",Dot,CS "0",Dot,CS "113",Dot,CS "3",Blank,RParen,Blank,Comment]
-- [CS "example",Dot,CS "com",Dot,Blank,CS "7200",Blank,CS "IN",Blank,CS "A",Blank,CS "203",Dot,CS "0",Dot,CS "113",Dot,CS "3"]
-- >>> normLine [Blank,Comment]
-- []
normLine :: Line -> Line
normLine s0
    | null s1                 = []
    | last s1 `elem` asBlank  = init s1  {- drop last blank -}
    | otherwise               = s1
  where
    s1 = rec_ id s0

    rec_ a []               = a []
    rec_ a (t:ts)
        | t `elem` asBlank  = blank (a . (Blank :))  ts
        | otherwise         = rec_  (a . (t :))      ts

    blank a []              = rec_   a               []
    blank a (t:ts)
        | t `elem` asBlank  = blank  a               ts
        | otherwise         = rec_  (a . (t :))      ts
    {- reduce some blanks to one -}
    asBlank = [Blank, Comment, LParen, RParen]
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- | convert to record separated tokens
normTokens :: [Line] -> [Token]
normTokens = concatMap (rsep . normLine) . reduceParens
  where
    {- skip blank record -}
    rsep     []    = []
    rsep xs@(_:_)  = xs ++ [RSep]
{- FOURMOLU_ENABLE -}

---

data Record
    = R_Origin Domain
    | R_TTL TTL
    | R_RR ResourceRecord
    deriving (Show)
