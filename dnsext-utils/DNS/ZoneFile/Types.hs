{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}

module DNS.ZoneFile.Types where

-- ghc packages
import Control.Applicative
import Control.Monad
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except
import Control.Monad.Trans.State
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Short as Short
import Data.Char (chr)
import Data.List (unfoldr)
import Data.Maybe (fromMaybe)
import Data.Monoid (Last (..))
import Data.Word (Word8)

-- dnsext-* packages
import DNS.Types
import qualified DNS.Types.Opaque as Opaque

class CaseCons t s | s -> t where
    caseCons :: (t -> s -> a) -> a -> s -> a

{- FOURMOLU_DISABLE -}
instance CaseCons Word8 LB.ByteString where
    caseCons c n bs
        | LB.null bs  = n
        | otherwise   = c (LB.head bs) (LB.tail bs)

instance CaseCons a [a] where
    caseCons c n xxs = case xxs of
        []      -> n
        x : xs  -> c x xs

takeCons :: CaseCons t s => Int -> s -> [t]
takeCons n s
    | n <= 0     = []
    | otherwise  = caseCons (\t ts -> t : takeCons (n-1) ts) [] s
{- FOURMOLU_ENABLE -}

---

type Error = Last String
type Parser t s = StateT s (Except Error)

runError :: Last String -> String
runError = fromMaybe "<empty error>" . getLast

runParser :: Parser t s a -> s -> Either String (a, s)
runParser p in_ = either (Left . runError) Right $ runExcept (runStateT p in_)

raise :: String -> Parser t s a
raise = lift . throwE . Last . Just

poly_token :: CaseCons t s => Parser t s t
poly_token = do
    s <- get
    caseCons
        (\t ts -> put ts *> pure t)
        (raise "token: eof")
        s

eof :: (Show t, CaseCons t s) => Parser t s ()
eof = do
    s <- get
    caseCons
        (\_ _ -> raise $ "eof: more inputs found: " ++ unwords (map show $ takeCons 7 s) ++ " ...")
        (pure ())
        s

satisfy :: (Show t, CaseCons t s) => String -> (t -> Bool) -> Parser t s t
satisfy name p = do
    t <- poly_token
    guard (p t) <|> raise ("satisfy: not satisfied, <" ++ name ++ "> predicate against " ++ show t)
    pure t

this :: (Eq t, Show t, CaseCons t s) => t -> Parser t s t
this tk = satisfy ("this " ++ show tk) (== tk)

these :: (Eq t, Show t, CaseCons t s) => [t] -> Parser t s [t]
these = mapM this

---

data Directive
    = D_Origin
    | D_TTL
    deriving (Eq, Show)

-- character-string or longer opaque-string
type CString = Short.ShortByteString

cstringW8 :: [Word8] -> CString
cstringW8 = Short.pack

txtCString :: CString -> Opaque
txtCString cs = Opaque.fromShortByteString $ Short.cons (fromIntegral $ Short.length cs) cs

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

---

type Line = [Token]

-- $setup
-- >>> :set -XOverloadedStrings

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
