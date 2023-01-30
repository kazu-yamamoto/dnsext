module Main (main) where

import DNS.Do53.Client (rdFlag, doFlag, QueryControls, FlagOp(..))
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (addResourceDataForSVCB)
import DNS.Types (TYPE(..), runInitIO)
import Data.List (isPrefixOf)
import System.Environment (getArgs)

import qualified DNS.Cache.Log as Log

import Operation (operate)
import FullResolve (fullResolve)
import Output (pprResult)

main :: IO ()
main = do
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    args <- getArgs
    let (at, plus, minus, targets) = divide args
    if "-h" `elem` minus || "--help" `elem` minus then
        putStr help
      else do
        let mserver = case at of
              []  -> Nothing
              x:_ -> Just $ drop 1 x
            mHostTyp = case targets of
              h:[]   -> Just (h, A)
              h:t:[] -> Just (h, read t)
              _      -> Nothing
            ctl = mconcat $ map toFlag plus
            full = "--full" `elem` minus
            disableV6NS = "-4" `elem` minus
        case mHostTyp of
          Nothing -> putStr help
          Just (host,typ)
            | full      -> do
                ex <- fullResolve disableV6NS Log.Stdout Log.INFO host typ
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
help =
  unlines
  [ "Usage: dug [@server] [name [query-type [query-option]]]"
  , ""
  , "         query-type: a | aaaa | ns | txt | ptr | ..."
  , "         query-option:"
  , "           +[no]rec[urse]  (Recursive mode)"
  , "           +[no]dnssec     (DNSSEC)"
  ]
