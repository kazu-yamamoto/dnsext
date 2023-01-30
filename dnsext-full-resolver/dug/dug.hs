{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Monad (when)
import DNS.Do53.Client (rdFlag, doFlag, QueryControls, FlagOp(..))
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (addResourceDataForSVCB)
import DNS.Types (TYPE(..), runInitIO)
import Data.List (isPrefixOf, intercalate)
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit (exitSuccess, exitFailure)

import qualified DNS.Cache.Log as Log

import Operation (operate)
import FullResolve (fullResolve)
import Output (pprResult)

options :: [OptDescr (Options -> Options)]
options = [
    Option ['h'] ["help"]
    (NoArg (\ opts -> opts { optHelp = True }))
    "print help"
  , Option ['i'] ["iterative"]
    (NoArg (\ opts -> opts { optIterative = True }))
    "resolve iteratively"
  , Option ['4'] ["ipv4"]
    (NoArg (\ opts -> opts { optDisableV6NS = True }))
    "disable IPv6 NS"
  ]

data Options = Options {
    optHelp        :: Bool
  , optIterative   :: Bool
  , optDisableV6NS :: Bool
  } deriving Show

defaultOptions :: Options
defaultOptions    = Options {
    optHelp        = False
  , optIterative   = False
  , optDisableV6NS = False
  }

main :: IO ()
main = do
    args <- getArgs
    let (at, plus, minus, targets) = divide args
    Options{..} <- case getOpt Permute options minus of
          (o,_,[])   -> return $ foldl (flip id) defaultOptions o
          (_,_,errs) -> do
              mapM_ putStr errs
              exitFailure
    when optHelp $ do
        putStr $ usageInfo help options
        exitSuccess
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    let mserver = case at of
          []  -> Nothing
          x:_ -> Just $ drop 1 x
        mHostTyp = case targets of
          h:[]   -> Just (h, A)
          h:t:[] -> Just (h, read t)
          _      -> Nothing
        ctl = mconcat $ map toFlag plus
    case mHostTyp of
      Nothing -> putStr help
      Just (host,typ)
        | optIterative -> do
            ex <- fullResolve optDisableV6NS Log.Stdout Log.INFO host typ
            case ex of
              Left err -> fail $ show err
              Right rs -> putStr $ pprResult rs
        | otherwise -> do
            ex <- operate mserver host typ ctl
            case ex of
              Left err -> fail $ show err
              Right rs -> putStr $ pprResult rs

divide :: [String] -> ([String],[String],[String],[String])
divide ls = loop ls (id,id,id,id)
  where
    loop [] (b0,b1,b2,b3) = (b0 [], b1 [], b2 [], b3 [])
    loop (x:xs) (b0,b1,b2,b3)
      | "@" `isPrefixOf` x = loop xs (b0 . (x:), b1, b2, b3)
      | "+" `isPrefixOf` x = loop xs (b0, b1 . (x:), b2, b3)
      | "-" `isPrefixOf` x = loop xs (b0, b1, b2 . (x:), b3)
      | otherwise          = loop xs (b0, b1, b2, b3 . (x:))

toFlag :: String -> QueryControls
toFlag "+rec"       = rdFlag FlagSet
toFlag "+recurse"   = rdFlag FlagSet
toFlag "+norec"     = rdFlag FlagClear
toFlag "+norecurse" = rdFlag FlagClear
toFlag "+dnssec"    = doFlag FlagSet
toFlag "+nodnssec"  = doFlag FlagClear
toFlag _            = mempty -- fixme

help :: String
help = intercalate "\n"
  [ "Usage: dug [@server] [name [query-type [query-option]]] [options]"
  , ""
  , "query-type: a | aaaa | ns | txt | ptr | ..."
  , ""
  , "query-option:"
  , "  +[no]rec[urse]  (Recursive mode)"
  , "  +[no]dnssec     (DNSSEC)"
  , ""
  , "options:"
  ]
