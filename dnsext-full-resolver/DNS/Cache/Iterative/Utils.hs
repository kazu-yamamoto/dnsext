{-# LANGUAGE OverloadedStrings #-}

module DNS.Cache.Iterative.Utils where

-- GHC packages
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Trans.Reader (asks)
import Data.Function (on)
import Data.List (groupBy, intercalate)

-- other packages

import System.Console.ANSI.Types

-- dns packages

import DNS.Types (
    DNSMessage,
 )
import qualified DNS.Types as DNS

-- this package

import DNS.Cache.Iterative.Types
import DNS.Cache.Types (NE)
import qualified DNS.Log as Log


logLines :: Log.Level -> [String] -> ContextT IO ()
logLines level xs = do
    putLines <- asks logLines_
    liftIO $ putLines level Nothing xs

logLn :: Log.Level -> String -> ContextT IO ()
logLn level = logLines level . (: [])

clogLn :: Log.Level -> Maybe Color -> String -> ContextT IO ()
clogLn level color s = do
    putLines <- asks logLines_
    liftIO $ putLines level color [s]

printResult :: Either QueryError DNSMessage -> IO ()
printResult = either print (putStr . unlines . concat . result)
  where
    result msg =
        [ "answer:" : map show (DNS.answer msg) ++ [""]
        , "authority:" : map show (DNS.authority msg) ++ [""]
        , "additional:" : map show (DNS.additional msg) ++ [""]
        ]

ppDelegation :: NE DEntry -> String
ppDelegation des =
    "\t"
        ++ ( intercalate "\n\t" $
                map (pp . bundle) $
                    groupBy ((==) `on` fst) $
                        map toT (fst des : snd des)
           )
  where
    toT (DEwithAx d i) = (d, show i)
    toT (DEonlyNS d) = (d, "")
    bundle xss@(x : _) = (fst x, filter (/= "") $ map snd xss)
    bundle [] = ("", []) -- never reach
    pp (d, is) = show d ++ " " ++ show is
