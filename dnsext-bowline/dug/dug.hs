{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Concurrent (forkIO, killThread)
import Control.Monad (when)
import DNS.Do53.Client (
    FlagOp (..),
    QueryControls,
    ResolveActionsFlag (..),
    adFlag,
    cdFlag,
    doFlag,
    rdFlag,
 )
import DNS.Do53.Internal (Reply (..), Result (..))
import DNS.DoX.Stub
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
import Recursive (recursiveQeury)

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
        []
        ["debug"]
        (NoArg (\opts -> opts{optLogLevel = Log.DEBUG}))
        "set the log level to DEBUG"
    , Option
        []
        ["warn"]
        (NoArg (\opts -> opts{optLogLevel = Log.WARN}))
        "set the log level to WARN"
    , Option
        []
        ["demo"]
        (NoArg (\opts -> opts{optLogLevel = Log.DEMO}))
        "set the log level to DEMO"
    , Option
        ['j']
        ["json"]
        (NoArg (\opts -> opts{optJSON = True}))
        "use JSON encoding"
    , Option
        ['m']
        ["multi"]
        (NoArg (\opts -> opts{optMultiline = True}))
        "use multiline output"
    ]

----------------------------------------------------------------

data Options = Options
    { optHelp :: Bool
    , optIterative :: Bool
    , optDisableV6NS :: Bool
    , optJSON :: Bool
    , optPort :: Maybe String
    , optDoX :: ShortByteString
    , optLogLevel :: Log.Level
    , optMultiline :: Bool
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optHelp = False
        , optIterative = False
        , optDisableV6NS = False
        , optJSON = False
        , optPort = Nothing
        , optDoX = "do53"
        , optLogLevel = Log.WARN
        , optMultiline = False
        }

----------------------------------------------------------------

main :: IO ()
main = do
    runInitIO $ do
        {- Override the parser behavior to accept the extended TYPE.
           Therefore, this action is required prior to reading the TYPE. -}
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    (args, Options{..}) <- getArgs >>= getArgsOpts
    when optHelp $ do
        putStr $ usageInfo help options
        putStrLn "\n  <proto> = auto|tcp|dot|doq|h2|h2c|h3"
        exitSuccess
    let (at, dtq) = partition ("@" `isPrefixOf`) args
    qs <- getQueries dtq
    port <- getPort optPort optDoX
    (logger, putLines, flush) <- Log.new Log.Stdout optLogLevel
    tid <- forkIO logger
    let raflags
            | optMultiline = [RAFlagMultiLine]
            | otherwise = []
    let putLn = mkPutline optMultiline optJSON putLines
    t0 <- T.getUnixTime
    ------------------------
    if optIterative
        then do
            when (not (null at)) $ do
                putStrLn "@ cannot used with '-i'"
                exitFailure
            target <- case qs of
                [] -> do
                    putStrLn "domain must be specified"
                    exitFailure
                [q] -> return q
                _ -> do
                    putStrLn "multiple domains must not be specified"
                    exitFailure
            ex <- iterativeQuery optDisableV6NS putLines target
            case ex of
                Left e -> fail e
                Right msg -> putLn msg
        else do
            let mserver = map (drop 1) at
            ex <- recursiveQeury mserver port optDoX putLines raflags $ head qs
            case ex of
                Left e -> fail (show e)
                Right r -> do
                    let h = mkHeader r
                        msg = replyDNSMessage (resultReply r)
                    putLines Log.WARN (Just Green) [h]
                    putLn msg
    ------------------------
    putTime t0 putLines
    killThread tid
    flush

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
    :: Bool
    -> Bool
    -> (Log.Level -> Maybe Color -> [String] -> IO ())
    -> DNSMessage
    -> IO ()
mkPutline multi json putLines msg = putLines Log.WARN Nothing [res msg]
  where
    oflags
        | multi = [Multiline]
        | otherwise = []
    res
        | json = showJSON
        | otherwise = pprResult oflags

----------------------------------------------------------------

mkHeader :: Result -> String
mkHeader Result{..} =
    ";; "
        ++ show resultIP
        ++ "#"
        ++ show resultPort
        ++ "/"
        ++ resultTag
        ++ ", Tx:"
        ++ show replyTxBytes
        ++ "bytes"
        ++ ", Rx:"
        ++ show replyRxBytes
        ++ "bytes"
  where
    Reply{..} = resultReply

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
