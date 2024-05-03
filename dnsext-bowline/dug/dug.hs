{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Concurrent (forkIO, killThread)
import Control.Monad (when)
import DNS.Do53.Client (
    FlagOp (..),
    QueryControls,
    adFlag,
    cdFlag,
    doFlag,
    rdFlag,
 )
import DNS.DoX.Client
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (ALPN, addResourceDataForSVCB)
import DNS.Types (
    CLASS (..),
    DNSMessage,
    Question (..),
    TYPE (..),
    fromRepresentation,
    runInitIO,
 )
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.List (intercalate, isPrefixOf, partition)
import qualified Data.UnixTime as T
import Network.Socket (PortNumber)
import System.Console.ANSI.Types
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import Text.Read (readMaybe)

import qualified DNS.Log as Log

import Iterative (iterativeQuery)
import JSON (showJSON)
import Output (OutputFlag (..), pprResult)
import Recursive (recursiveQuery)
import Types

----------------------------------------------------------------

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['h']
        ["help"]
        (NoArg (\opts -> opts{optHelp = True}))
        "print help"
    , Option
        ['i']
        ["iterative"]
        (NoArg (\opts -> opts{optIterative = True}))
        "resolve iteratively"
    , Option
        ['4']
        ["ipv4"]
        (NoArg (\opts -> opts{optDisableV6NS = True}))
        "disable IPv6 NS"
    , Option
        ['p']
        ["port"]
        (ReqArg (\port opts -> opts{optPort = Just port}) "<port>")
        "specify port number"
    , Option
        ['d']
        ["dox"]
        ( ReqArg
            (\dox opts -> opts{optDoX = convDoX dox})
            "<proto>"
        )
        "enable DoX"
    , Option
        ['f']
        ["format"]
        ( ReqArg
            (\fmt opts -> opts{optFormat = convOutputFlag fmt})
            "<format>"
        )
        "set the output format"
    , Option
        ['v']
        ["verbose"]
        ( ReqArg
            (\n opts -> opts{optLogLevel = convLogLevel n})
            "<verbosity>"
        )
        "set the verbosity"
    , Option
        ['r']
        ["resumption-file"]
        ( ReqArg
            (\file opts -> opts{optResumptionFile = Just file})
            "<file>"
        )
        "specify a file to save resumption information"
    , Option
        ['0']
        ["0rtt"]
        (NoArg (\opts -> opts{opt0RTT = True}))
        "use 0-RTT (aka early data)"
    , Option
        ['l']
        ["keylog-file"]
        ( ReqArg
            (\file opts -> opts{optKeyLogFile = Just file})
            "<file>"
        )
        "specify a file to save TLS main secret keys"
    ]

----------------------------------------------------------------

main :: IO ()
main = do
    runInitIO $ do
        {- Override the parser behavior to accept the extended TYPE.
           Therefore, this action is required prior to reading the TYPE. -}
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    (args, opts@Options{..}) <- getArgs >>= getArgsOpts
    when optHelp $ do
        putStr $ usageInfo help options
        putStr "\n"
        putStrLn "  <proto>     = auto | tcp | dot | doq | h2 | h2c | h3"
        putStrLn "  <format>    = multi | json"
        putStrLn "  <verbosity> = 0 | 1 | 2"
        exitSuccess
    ------------------------
    (at, port, qs, logger, putLn, putLines, flush) <- cookOpts args opts
    tid <- forkIO logger
    t0 <- T.getUnixTime
    ------------------------
    if optIterative
        then do
            target <- checkIterative at qs
            iterativeQuery optDisableV6NS putLn putLines target
        else do
            let mserver = map (drop 1) at
            recursiveQuery mserver port putLn putLines qs opts
    ------------------------
    putTime t0 putLines
    killThread tid
    flush

----------------------------------------------------------------

cookOpts
    :: [String]
    -> Options
    -> IO
        ( [String]
        , PortNumber
        , [(Question, QueryControls)]
        , IO ()
        , DNSMessage -> IO ()
        , Log.PutLines
        , IO ()
        )
cookOpts args Options{..} = do
    let (at, dtq) = partition ("@" `isPrefixOf`) args
    qs <- getQueries dtq
    port <- getPort optPort optDoX
    (logger, putLines, flush) <- Log.new Log.Stdout optLogLevel
    let putLn = mkPutline optFormat putLines
    return (at, port, qs, logger, putLn, putLines, flush)

----------------------------------------------------------------

checkIterative
    :: [String]
    -> [(Question, QueryControls)]
    -> IO (Question, QueryControls)
checkIterative at qs = do
    when (not (null at)) $ do
        putStrLn "@ cannot used with '-i'"
        exitFailure
    case qs of
        [] -> do
            putStrLn "domain must be specified"
            exitFailure
        [q] -> return q
        _ -> do
            putStrLn "multiple domains must not be specified"
            exitFailure

----------------------------------------------------------------

putTime
    :: T.UnixTime
    -> (Log.Level -> Maybe Color -> [String] -> IO ())
    -> IO ()
putTime t0 putLines = do
    t1 <- T.getUnixTime
    let T.UnixDiffTime s u = t1 `T.diffUnixTime` t0
    let sec = if s /= 0 then show s ++ "sec " else ""
        tm =
            ";; "
                ++ sec
                ++ show (u `div` 1000)
                ++ "usec"
    putLines Log.WARN (Just Green) [tm]

----------------------------------------------------------------

mkPutline
    :: OutputFlag
    -> (Log.Level -> Maybe Color -> [String] -> IO ())
    -> DNSMessage
    -> IO ()
mkPutline format putLines msg = putLines Log.WARN Nothing [res msg]
  where
    res = case format of
        JSONstyle -> showJSON
        Singleline -> pprResult []
        Multiline -> pprResult [Multiline]

----------------------------------------------------------------

getArgsOpts :: [String] -> IO ([String], Options)
getArgsOpts args = case getOpt Permute options args of
    (o, n, []) -> return (n, foldl (flip id) defaultOptions o)
    (_, _, errs) -> do
        mapM_ putStr errs
        exitFailure

----------------------------------------------------------------

getQueries :: [String] -> IO [(Question, QueryControls)]
getQueries xs0 = loop xs0 id
  where
    loop [] build = return $ build []
    loop xs build = do
        (q, ys) <- getQuery xs
        loop ys (build . (q :))

-- Question d t IN
getQuery :: [String] -> IO ((Question, QueryControls), [String])
getQuery [] = do
    putStrLn "never reach"
    exitFailure
getQuery (x : xs)
    | '.' `notElem` x = do
        putStrLn $ show x ++ " does not contain '.'"
        exitFailure
    | otherwise = do
        let d = fromRepresentation x
        case xs of
            [] -> return ((Question d A IN, mempty), [])
            y : ys
                | '.' `elem` y -> return ((Question d A IN, mempty), xs)
                | "+" `isPrefixOf` y -> do
                    let (qs, zs) = span ("+" `isPrefixOf`) ys
                        qctls = mconcat $ map toFlag (y : qs)
                    return ((Question d A IN, qctls), zs)
                | otherwise -> do
                    let mtyp = readMaybe y
                    case mtyp of
                        Nothing -> do
                            putStrLn $ "Type " ++ y ++ " is not supported"
                            exitFailure
                        Just typ -> do
                            let (qs, zs) = span ("+" `isPrefixOf`) ys
                                qctls = mconcat $ map toFlag qs
                            return ((Question d typ IN, qctls), zs)

----------------------------------------------------------------

getPort :: Maybe String -> ALPN -> IO PortNumber
getPort Nothing optDoX = return $ doxPort optDoX
getPort (Just x) _ = case readMaybe x of
    Just p -> return p
    Nothing -> do
        putStrLn $ "Port " ++ x ++ " is illegal"
        exitFailure

{- FOURMOLU_DISABLE -}
convDoX :: String -> ShortByteString
convDoX dox = case dox' of
  "http2" -> "h2"
  "http3" -> "h3"
  "quic"  -> "doq"
  "tls"   -> "dot"
  x       -> Short.toShort x
  where
    dox' = C8.pack dox

convOutputFlag :: String -> OutputFlag
convOutputFlag "json"  = JSONstyle
convOutputFlag "multi" = Multiline
convOutputFlag _       = Singleline

convLogLevel :: String -> Log.Level
convLogLevel "0" = Log.WARN
convLogLevel "1" = Log.DEMO
convLogLevel _ = Log.DEBUG

----------------------------------------------------------------

toFlag :: String -> QueryControls
toFlag "+rec"       = rdFlag FlagSet
toFlag "+recurse"   = rdFlag FlagSet
toFlag "+norec"     = rdFlag FlagClear
toFlag "+norecurse" = rdFlag FlagClear
toFlag "+dnssec"    = doFlag FlagSet
toFlag "+nodnssec"  = doFlag FlagClear
toFlag "+rdflag"    = rdFlag FlagSet
toFlag "+nordflag"  = rdFlag FlagClear
toFlag "+doflag"    = doFlag FlagSet
toFlag "+nodoflag"  = doFlag FlagClear
toFlag "+cdflag"    = cdFlag FlagSet
toFlag "+nocdflag"  = cdFlag FlagClear
toFlag "+adflag"    = adFlag FlagSet
toFlag "+noadflag"  = adFlag FlagClear
toFlag _            = mempty
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

help :: String
help =
    intercalate
        "\n"
        [ "Usage: dug [options] [@server]* [name [query-type [query-option]]]+"
        , ""
        , "query-type: a | aaaa | ns | txt | ptr | ..."
        , ""
        , "query-option:"
        , "  +[no]rdflag: [un]set RD (Recursion Desired) bit, +[no]rec[curse]"
        , "  +[no]doflag: [un]set DO (DNSSEC OK) bit, +[no]dnssec"
        , "  +[no]cdflag: [un]set CD (Checking Disabled) bit"
        , "  +[no]adflag: [un]set AD (Authentic Data) bit"
        , ""
        , "options:"
        ]
