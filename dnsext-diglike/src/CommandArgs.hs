module CommandArgs where

import Control.Applicative ((<|>), optional)
import Control.Monad (guard)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (Except, runExcept, throwE)
import Control.Monad.Trans.State (StateT (..), get, put)
import Data.Functor (($>))
import Data.Char (toUpper)
import Data.Monoid (Last (..))

import DNS.Types (TYPE (A, NS, TXT, PTR, AAAA, SOA))
import DNS.IO.Types (QueryControls, rdFlag, FlagOp (FlagClear, FlagSet))


-- parse command args to get params

help :: String
help =
  unlines
  [ "Usage: diglike [@server] [name [query-type [query-option]]]"
  , ""
  , "         query-type: a | ns | txt | ptr"
  , "         query-option:"
  , "           +[no]rec[urse]  (Recursive mode)"
  ]

parseParams :: [String] -> Either String (Params, [String])
parseParams = runArgsParser params

type Params = (((Maybe String, String), TYPE), QueryControls)

params :: ArgsP Params
params =
  eoi $> (((Nothing, "."), NS), mempty)
  <|>
  do server <- takeServer
     name   <- eoi $> "." <|> takeName
     typ    <- eoi $> A   <|> takeTYPE
     qopt   <- eoi $> mempty <|> takeQueryOpt

     return (((server, name), typ), qopt)

  where
    takeServer = optional $ drop 1 <$> satisfy ((== "@") . take 1)
    takeName = arg
    takeTYPE = do
      x <- arg
      maybe (errorM $ "parseArgs: unimplemented RR type: " ++ x) pure $ decodeTYPE x
    takeQueryOpt = do
      opt <- satisfy ((== "+") . take 1)
      let returnRD = return . rdFlag
      case opt of
        "+rec"        -> returnRD FlagSet
        "+recurse"    -> returnRD FlagSet
        "+norec"      -> returnRD FlagClear
        "+norecurse"  -> returnRD FlagClear
        _             -> errorM $ "parseArgs: unimplemented query option: " ++ opt

decodeTYPE :: String -> Maybe TYPE
decodeTYPE tn = case map toUpper tn of
  "A"    ->  Just A
  "AAAA" ->  Just AAAA
  "NS"   ->  Just NS
  "TXT"  ->  Just TXT
  "PTR"  ->  Just PTR
  "SOA"  ->  Just SOA
  _      ->  Nothing

---

-- parser for command args

type Error = Last String
type ArgsP = StateT [String] (Except Error)

{-# ANN unError "HLint: ignore Use fromMaybe" #-}
unError :: Last String -> String
unError = maybe "<error: empty message>" id . getLast

errorM :: String -> ArgsP a
errorM = lift . throwE . Last . Just

runArgsParser :: ArgsP a -> [String] -> Either String (a, [String])
runArgsParser p = either (Left . unError) Right . runExcept . runStateT p

arg :: ArgsP String
arg = do
  args <- get
  case args of
    []    -> errorM "arg: argument required."
    a:as  -> put as $> a

satisfy :: (String -> Bool) -> ArgsP String
satisfy p = do
  a <- arg
  guard $ p a
  pure a

eoi :: ArgsP ()
eoi = do
  args <- get
  case args of
    []   -> pure ()
    _:_  -> errorM "eoi: more arguments found."
