module Main (main) where

import DNS.IO (rdFlag, QueryControls, FlagOp(..))
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.Types (TYPE(..), runInitIO)
import Data.List (isPrefixOf)
import System.Environment (getArgs)

import Operation (operate)
import Output (pprResult)

main :: IO ()
main = do
    runInitIO addResourceDataForDNSSEC
    args <- getArgs
    let printResult = putStr . pprResult args
        (at, plus, minus, targets) = divide args
    if "-h" `elem` minus || "--help" `elem` minus then
        putStr help
      else do
        let mserver = case at of
              []  -> Nothing
              x:_ -> Just $ drop 1 x
            mHostTyp = case targets of
              h:[]   -> Just (h,A)
              h:t:[] -> Just (h, read t)
              _      -> Nothing
            ctl = mconcat $ map toFlag plus
        case mHostTyp of
          Nothing -> putStr help
          Just (host,typ) -> do
              ex <- operate mserver host typ ctl
              case ex of
                Left err -> fail $ show err
                Right rs -> printResult rs

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
toFlag _            = mempty -- fixme

help :: String
help =
  unlines
  [ "Usage: dug [@server] [name [query-type [query-option]]]"
  , ""
  , "         query-type: a | ns | txt | ptr"
  , "         query-option:"
  , "           +[no]rec[urse]  (Recursive mode)"
  ]
