{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Monad (when)
import DNS.Do53.Client (rdFlag, doFlag, QueryControls, FlagOp(..))
import DNS.Do53.Internal (Result(..), Reply(..))
import DNS.DoX.Stub
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (addResourceDataForSVCB)
import DNS.Types (TYPE(..), runInitIO)
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.List (isPrefixOf, intercalate)
import qualified Data.UnixTime as T
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit (exitSuccess, exitFailure)
import Text.Read (readMaybe)

import qualified DNS.Cache.Log as Log
import DNS.Cache.Iterative
  (RequestDO (..), RequestCD (..), RequestAD (..), setRequestDO, setRequestCD, setRequestAD,
   IterativeControls (..), defaultIterativeControls)

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
  , Option ['p'] ["port"]
    (ReqArg (\ port opts -> opts { optPort = Just port }) "<port>")
    "specify port number"
  , Option ['d'] ["dox"]
    (ReqArg (\ dox opts -> opts { optDoX = Short.toShort (C8.pack dox) }) "auto|dot|doq|h2|h3")
    "enable DoX"
  ]

data Options = Options {
    optHelp        :: Bool
  , optIterative   :: Bool
  , optDisableV6NS :: Bool
  , optPort        :: Maybe String
  , optDoX         :: ShortByteString
  } deriving Show

defaultOptions :: Options
defaultOptions    = Options {
    optHelp        = False
  , optIterative   = False
  , optDisableV6NS = False
  , optPort        = Nothing
  , optDoX         = "do53"
  }

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
    (dom,typ) <- case targets of
          [h]   -> return (h, A)
          [h,t] -> do
              let mtyp' = readMaybe t
              case mtyp' of
                Just typ' -> return (h, typ')
                Nothing   -> do
                    putStrLn $ "Type " ++ t ++ " is not supported"
                    exitFailure
          _     -> do
                  putStrLn "One or two arguments are necessary"
                  exitFailure
    port <- case optPort of
      Nothing -> return $ doxPort optDoX
      Just x  -> case readMaybe x of
        Just p -> return p
        Nothing -> do
            putStrLn $ "Port " ++ x ++ " is illegal"
            exitFailure
    let mserver = map (drop 1) at
        ctl = mconcat $ map toFlag plus
    if optIterative then do
        let ustep tbl f s = maybe f id $ lookup s tbl
            uflag tbl d = foldl (ustep tbl) d plus
            update get set tbl s = set (uflag tbl $ get s) s
            flagDO = update requestDO setRequestDO tblFlagDO
            flagCD = update requestCD setRequestCD tblFlagCD
            flagAD = update requestAD setRequestAD tblFlagAD
            ictl = flagAD . flagCD . flagDO $ defaultIterativeControls
        ex <- fullResolve optDisableV6NS Log.Stdout Log.INFO ictl dom typ
        case ex of
          Left err -> fail $ show err
          Right rs -> putStr $ pprResult rs
      else do
        t0 <- T.getUnixTime
        ex <- operate mserver port optDoX dom typ ctl
        t1 <- T.getUnixTime
        case ex of
          Left err -> fail $ show err
          Right Result{..} -> do
              let Reply{..} = resultReply
              putStr $ ";; " ++ resultHostName ++ "#" ++ show resultPortNumber ++ "/" ++ resultTag
              putStr $ ", Tx:" ++ show replyTxBytes ++ "bytes"
              putStr $ ", Rx:" ++ show replyRxBytes ++ "bytes"
              putStr   ", "
              let T.UnixDiffTime s u = (t1 `T.diffUnixTime` t0)
              when (s /= 0) $ putStr $ show s ++ "sec "
              putStr $ show (u `div` 1000) ++ "usec"
              putStr "\n\n"
              putStr $ pprResult replyDNSMessage

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

tblFlagDO :: [(String, RequestDO)]
tblFlagDO = [("+dnssec", DnssecOK), ("+nodnssec", NoDnssecOK)]

tblFlagCD :: [(String, RequestCD)]
tblFlagCD = [("+cdflag", CheckDisabled), ("+nocdflag", NoCheckDisabled)]

tblFlagAD :: [(String, RequestAD)]
tblFlagAD = [("+adflag", AuthenticatedData), ("+noadflag", NoAuthenticatedData)]

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
