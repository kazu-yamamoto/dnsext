
module DNSC.ServerMonitor where

-- GHC packages
import Control.Monad (unless)
import Data.Functor (($>))
import Data.Ord (Down (..))
import Data.List (isInfixOf, find)
import Data.Char (toUpper)
import qualified Data.ByteString.Char8 as B8

-- dns packages
import qualified Network.DNS as DNS

-- this package
import DNSC.Iterative (Context (..))

data Command
  = Find String
  | Lookup DNS.Domain DNS.TYPE
  | Size
  | Noop
  | Quit
  deriving Show

monitor :: Context -> IO () -> IO ()
monitor cxt quit = loop
  where
    parseTYPE s =
      find match types
      where
        us = map toUpper s
        match t = show t == us
        types = map DNS.toTYPE [1..512]
    parseCmd []  =    Just Noop
    parseCmd ws  =  case ws of
      "find" : s : _      ->  Just $ Find s
      ["lookup", n, typ]  ->  Lookup (B8.pack n) <$> parseTYPE typ
      "size" : _  ->  Just Size
      "quit" : _  ->  Just Quit
      _           ->  Nothing

    runCmd Quit  =  quit $> True
    runCmd cmd   =  dispatch cmd $> False
      where
        dispatch Noop             =  return ()
        dispatch (Find s)         =  mapM_ putStrLn . filter (s `isInfixOf`) . map show =<< dump_ cxt
        dispatch (Lookup dom typ) =  maybe (putStrLn "miss.") hit =<< lookup_ cxt dom typ DNS.classIN
          where hit (rrs, Down rank) = mapM_ putStrLn $ ("hit: " ++ show rank) : map show rrs
        dispatch Size             =  print =<< size_ cxt
        dispatch x                =  putStrLn $ "command: unknown state: " ++ show x

    loop = do
      putStr "\nmonitor:\n"
      s <- getLine
      isQuit <- maybe (putStrLn "command: parse error" $> False) runCmd $ parseCmd $ words s
      unless isQuit loop
