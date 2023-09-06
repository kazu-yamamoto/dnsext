{-# LANGUAGE OverloadedStrings #-}

module DNS.Cache.Iterative.Utils where

-- GHC packages

-- other packages

-- dnsext packages
import qualified DNS.Log as Log
import DNS.Types (DNSMessage)
import qualified DNS.Types as DNS
import System.Console.ANSI.Types

-- this package
import DNS.Cache.Imports
import DNS.Cache.Iterative.Types
import DNS.Cache.Types (NE)

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

{- FOURMOLU_DISABLE -}
data PPMode
    = PPShort
    | PPFull
    deriving Show

putDelegation :: Applicative f => PPMode -> NE DEntry -> (String -> f ()) -> (String -> f ()) -> f ()
putDelegation pprs des h fallback  = case pprs of
    PPFull   -> h ppFull
    PPShort  -> h ppShort *> unless (null suffix) (fallback ppFull)
  where
    ppFull  = "\t" ++ intercalate "\n\t" (map fst pps)
    ppShort = "\t" ++ intercalate "\n\t" (map fst hd ++ suffix)
    suffix = [ "... " ++ note  ++ " ..." | not $ null tl ]
    note = "plus " ++ show (length tl) ++ " names and " ++ show (sum $ map snd tl) ++ " glues"
    (hd, tl) = splitAt 2 pps
    pps = ppDelegations des
{- FOURMOLU_ENABLE -}

ppDelegation :: NE DEntry -> String
ppDelegation des = "\t" ++ intercalate "\n\t" (map fst $ ppDelegations des)

ppDelegations :: NE DEntry -> [(String, Int)]
ppDelegations des =
    map (pp . bundle) $ groupBy ((==) `on` fst) $ map toT (fst des : snd des)
  where
    toT (DEwithAx d i) = (d, show i)
    toT (DEonlyNS d) = (d, "")
    bundle xss@(x : _) = (fst x, filter (/= "") $ map snd xss)
    bundle [] = ("", []) -- never reach
    pp (d, is) = (show d ++ " " ++ show is, length is)
