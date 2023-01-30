{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import qualified Control.Exception as E
import Control.Monad (when)
import DNS.Do53.Client (rdFlag, doFlag, QueryControls, FlagOp(..))
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (addResourceDataForSVCB)
import DNS.Types (TYPE(..), runInitIO)
import Data.List (isPrefixOf, intercalate)
import Network.Socket ()
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit (exitSuccess, exitFailure)

import qualified DNS.Cache.Log as Log

import Operation (operate)
import FullResolve (fullResolve)
import Output (pprResult)

data DoX = Do53 | Auto | DoT | DoQ | DoH2 | DoH3 deriving (Eq, Show)

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
  , Option ['p'] ["port"]
    (ReqArg (\ port opts -> opts { optPort = Just port }) "<port>")
    "specify port number"
  , Option ['d'] ["dox"]
    (ReqArg (\ dox opts -> opts { optDoX = toDoX dox }) "dot|doq|doh2|doh3")
    "enable DoX (auto if unknown"
  ]

toDoX :: String -> DoX
toDoX "dot"  = DoT
toDoX "doq"  = DoQ
toDoX "doh2" = DoH2
toDoX "doh3" = DoH3
toDoX _      = Auto

data Options = Options {
    optHelp        :: Bool
  , optIterative   :: Bool
  , optDisableV6NS :: Bool
  , optPort        :: Maybe String
  , optDoX         :: DoX
  } deriving Show

defaultOptions :: Options
defaultOptions    = Options {
    optHelp        = False
  , optIterative   = False
  , optDisableV6NS = False
  , optPort        = Nothing
  , optDoX         = Do53
  }

readCatch :: Read a => String -> IO a
readCatch x = E.evaluate (read x) `E.catch` \(E.SomeException _) -> do
    putStrLn $ "Type " ++ x ++ " is not supported"
    exitFailure

main :: IO ()
main = do
    args <- getArgs
    (args', Options{..}) <- case getOpt Permute options args of
          (o,n,[])   -> return (n, foldl (flip id) defaultOptions o)
          (_,_,errs) -> do
              mapM_ putStr errs
              exitFailure
    when optHelp $ do
        putStr $ usageInfo help options
        exitSuccess
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    let (at, plus, targets) = divide args'
    (host,typ) <- case targets of
          [h]   -> return (h,A)
          [h,t] -> do
              typ' <- readCatch t
              return (h,typ')
          _     -> do
                  putStrLn "One or two arguments are necessary"
                  exitFailure
    port <- case optPort of
      Nothing -> return $ case optDoX of
        Do53 -> 53
        Auto -> 53
        DoT  -> 853
        DoQ  -> 443
        DoH2 -> 443
        DoH3 -> 443
      Just x  -> readCatch x
    let mserver = case at of
          []  -> Nothing
          x:_ -> Just $ drop 1 x
        ctl = mconcat $ map toFlag plus
    if optIterative then do
        ex <- fullResolve optDisableV6NS Log.Stdout Log.INFO host typ
        case ex of
          Left err -> fail $ show err
          Right rs -> putStr $ pprResult rs
      else do
        ex <- operate mserver port host typ ctl
        case ex of
          Left err -> fail $ show err
          Right rs -> putStr $ pprResult rs

divide :: [String] -> ([String],[String],[String])
divide ls = loop ls (id,id,id)
  where
    loop [] (b0,b1,b2) = (b0 [], b1 [], b2 [])
    loop (x:xs) (b0,b1,b2)
      | "@" `isPrefixOf` x = loop xs (b0 . (x:), b1, b2)
      | "+" `isPrefixOf` x = loop xs (b0, b1 . (x:), b2)
      | otherwise          = loop xs (b0, b1, b2 . (x:))

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
