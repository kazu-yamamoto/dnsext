{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Monad (when)
import DNS.Do53.Client (
    FlagOp (..),
    QueryControls,
    adFlag,
    cdFlag,
    doFlag,
    rdFlag,
 )
import DNS.Do53.Internal (Reply (..), Result (..))
import DNS.DoX.Stub
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (ALPN, addResourceDataForSVCB)
import DNS.Types (TYPE (..), runInitIO)
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as Short
import Data.List (intercalate, isPrefixOf)
import qualified Data.UnixTime as T
import Network.Socket (PortNumber)
import System.Console.ANSI.Types
import System.Console.GetOpt
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import Text.Read (readMaybe)

import qualified DNS.Log as Log

import Iterative (iterativeQuery)
import Output (pprResult)
import Recursive (recursiveQeury)

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
            (\dox opts -> opts{optDoX = Short.toShort (C8.pack dox)})
            "auto|dot|doq|h2|h3"
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
    ]

data Options = Options
    { optHelp :: Bool
    , optIterative :: Bool
    , optDisableV6NS :: Bool
    , optPort :: Maybe String
    , optDoX :: ShortByteString
    , optLogLevel :: Log.Level
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optHelp = False
        , optIterative = False
        , optDisableV6NS = False
        , optPort = Nothing
        , optDoX = "do53"
        , optLogLevel = Log.WARN
        }

main :: IO ()
main = do
    (args, Options{..}) <- getArgs >>= getArgsOpts
    when optHelp $ do
        putStr $ usageInfo help options
        exitSuccess
    let (at, plus, targets) = divide args
    (dom, typ) <- getDomTyp targets
    port <- getPort optPort optDoX
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    (putLines, _, terminate) <- Log.new Log.Stdout optLogLevel
    ----
    t0 <- T.getUnixTime
    (msg, header) <-
        if optIterative
            then do
                let ctl = mconcat $ map toFlag plus
                ex <- iterativeQuery optDisableV6NS putLines ctl dom typ
                case ex of
                    Left e -> terminate >> fail e
                    Right msg -> return (msg, ";; ")
            else do
                let mserver = map (drop 1) at
                    ctl = mconcat $ map toFlag plus
                ex <- recursiveQeury mserver port optDoX putLines ctl dom typ
                case ex of
                    Left e -> terminate >> fail (show e)
                    Right Result{..} -> do
                        let Reply{..} = resultReply
                        let h =
                                ";; "
                                    ++ resultHostName
                                    ++ "#"
                                    ++ show resultPortNumber
                                    ++ "/"
                                    ++ resultTag
                                    ++ ", Tx:"
                                    ++ show replyTxBytes
                                    ++ "bytes"
                                    ++ ", Rx:"
                                    ++ show replyRxBytes
                                    ++ "bytes"
                                    ++ ", "
                        return (replyDNSMessage, h)
    t1 <- T.getUnixTime
    let T.UnixDiffTime s u = (t1 `T.diffUnixTime` t0)
    let sec = if s /= 0 then show s ++ "sec " else ""
        tm =
            header
                ++ sec
                ++ show (u `div` 1000)
                ++ "usec"
                ++ "\n"
    putLines Log.WARN (Just Green) [tm]
    putLines Log.WARN Nothing [pprResult msg]
    terminate

----------------------------------------------------------------

divide :: [String] -> ([String], [String], [String])
divide ls = loop ls (id, id, id)
  where
    loop [] (b0, b1, b2) = (b0 [], b1 [], b2 [])
    loop (x : xs) (b0, b1, b2)
        | "@" `isPrefixOf` x = loop xs (b0 . (x :), b1, b2)
        | "+" `isPrefixOf` x = loop xs (b0, b1 . (x :), b2)
        | otherwise = loop xs (b0, b1, b2 . (x :))

----------------------------------------------------------------

getArgsOpts :: [String] -> IO ([String], Options)
getArgsOpts args = case getOpt Permute options args of
    (o, n, []) -> return (n, foldl (flip id) defaultOptions o)
    (_, _, errs) -> do
        mapM_ putStr errs
        exitFailure

getDomTyp :: [String] -> IO (String, TYPE)
getDomTyp [h] = return (h, A)
getDomTyp [h, t] = do
    let mtyp' = readMaybe t
    case mtyp' of
        Just typ' -> return (h, typ')
        Nothing -> do
            putStrLn $ "Type " ++ t ++ " is not supported"
            exitFailure
getDomTyp _ = do
    putStrLn "One or two arguments are necessary"
    exitFailure

getPort :: Maybe String -> ALPN -> IO PortNumber
getPort Nothing optDoX = return $ doxPort optDoX
getPort (Just x) _ = case readMaybe x of
    Just p -> return p
    Nothing -> do
        putStrLn $ "Port " ++ x ++ " is illegal"
        exitFailure

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
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
toFlag _            = mempty -- fixme
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

help :: String
help =
    intercalate
        "\n"
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
