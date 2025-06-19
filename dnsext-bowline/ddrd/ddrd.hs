{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import Data.IORef
import Data.IP ()
import Data.List
import qualified Data.List.NonEmpty as NE
import qualified Data.Map as Map
import Data.Maybe
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import System.Console.GetOpt
import System.Environment
import System.Exit

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Client
import DNS.SEC
import DNS.SVCB
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode

----------------------------------------------------------------

data Options = Options
    { optHelp :: Bool
    , optDebug :: Bool
    }

defaultOptions :: Options
defaultOptions =
    Options
        { optHelp = False
        , optDebug = False
        }

options :: [OptDescr (Options -> Options)]
options =
    [ Option
        ['h']
        ["help"]
        (NoArg (\opts -> opts{optHelp = True}))
        "print help"
    , Option
        ['d']
        ["debug"]
        (NoArg (\opts -> opts{optDebug = True}))
        "print debug info"
    ]

usage :: String
usage = "Usage: ddrd [OPTION] ipaddr [ipaddr...]"

showUsageAndExit :: IO a
showUsageAndExit = do
    putStrLn $ usageInfo usage options
    exitFailure

parseOpts :: [String] -> IO (Options, [String])
parseOpts argv =
    case getOpt Permute options argv of
        (o, n, []) -> return (foldl (flip id) defaultOptions o, n)
        (_, _, _errs) -> showUsageAndExit

----------------------------------------------------------------

serverAddr :: String
serverAddr = "127.0.0.1"

serverPort :: String
serverPort = "53"

serverResolve :: HostName -> ServiceName -> IO AddrInfo
serverResolve addr port = NE.head <$> getAddrInfo (Just hints) (Just addr) (Just port)
  where
    hints =
        defaultHints
            { addrFlags = [AI_NUMERICHOST, AI_NUMERICSERV, AI_PASSIVE]
            , addrSocketType = Datagram
            }

serverSocket :: AddrInfo -> IO Socket
serverSocket ai = E.bracketOnError (openSocket ai) close $ \s -> do
    setSocketOption s ReuseAddr 1
    bind s $ addrAddress ai
    return s

----------------------------------------------------------------

printDebug :: Options -> String -> IO ()
printDebug opts msg = when (optDebug opts) $ putStrLn msg

----------------------------------------------------------------

main :: IO ()
main = do
    args <- getArgs
    (opts, ips) <- parseOpts args
    when (optHelp opts) showUsageAndExit
    when (null ips) showUsageAndExit
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    ai <- serverResolve serverAddr serverPort
    E.bracket (serverSocket ai) close $ \s -> do
        ref <- newIORef Map.empty
        let conf = makeConf ref ips
        withLookupConf conf $ mainLoop opts s

mainLoop :: Options -> Socket -> LookupEnv -> IO ()
mainLoop opts s env = loop
  where
    loop = do
        bssa <- NSB.recvFrom s 2048
        mPiplineResolver <- selectSVCB <$> lookupSVCBInfo env
        case mPiplineResolver of
            Nothing -> printDebug opts "SVCB RR is not available"
            Just piplineResolver -> do
                printDebug opts "Running a pipeline resolver"
                piplineResolver (serverLoop opts s bssa) `E.catch` ignore
        loop
    ignore (E.SomeException se) = printDebug opts $ show se

serverLoop :: Options -> Socket -> (ByteString, SockAddr) -> Resolver -> IO ()
serverLoop opts s (bs0, sa0) resolver = do
    sendReply bs0 sa0
    loop
  where
    loop = do
        (bs, sa) <- NSB.recvFrom s 2048
        sendReply bs sa
        loop
    sendReply bs sa =
        case decode bs of
            Left _ -> printDebug opts "Decode error"
            Right msg -> case question msg of
                [] -> printDebug opts "No questions"
                q : _ -> do
                    printDebug opts $ "Q: " ++ pprDomain (qname q) ++ " " ++ show (qtype q)
                    let idnt = identifier msg
                    eres <- resolver q mempty
                    case eres of
                        Left _ -> printDebug opts "No reply"
                        Right res -> do
                            let msg' =
                                    (replyDNSMessage res)
                                        { identifier = idnt
                                        }
                            printDebug opts $ "R: " ++ intercalate "\n   " (map pprRR (answer msg'))
                            void $ NSB.sendTo s (encode msg') sa

pprDomain :: Domain -> String
pprDomain = init . toRepresentation

pprRR :: ResourceRecord -> String
pprRR ResourceRecord{..} = pprDomain rrname ++ " " ++ show rrtype ++ " " ++ show rdata

----------------------------------------------------------------

selectSVCB :: Either DNSError [[SVCBInfo]] -> Maybe PipelineResolver
selectSVCB (Left _) = Nothing
selectSVCB (Right []) = Nothing
selectSVCB (Right (sis : _)) =
    listToMaybe $
        catMaybes $
            map listToMaybe $
                toPipelineResolvers $
                    map modifyForDDR sis

makeConf
    :: IORef (Map.Map NameTag ByteString)
    -> [String]
    -> LookupConf
makeConf ref addrs =
    defaultLookupConf
        { lconfCacheConf = Just defaultCacheConf
        , lconfConcurrent = True
        , lconfSeeds = SeedsAddrs $ map read addrs
        , lconfActions =
            actions
                { ractionUseEarlyData = True
                , ractionValidate = False
                , ractionResumptionInfo = \tag -> do
                    m <- readIORef ref
                    case Map.lookup tag m of
                        Nothing -> return []
                        Just x -> return [x]
                , ractionOnResumptionInfo = \tag bs ->
                    atomicModifyIORef' ref $ \m -> (Map.insert tag bs m, ())
                }
        }
  where
    actions = lconfActions defaultLookupConf
