{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent.STM (atomically)
import qualified Control.Exception as E
import Control.Monad (void, when)
import Data.ByteString (ByteString)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import Data.IP ()
import Data.List (intercalate)
import qualified Data.List.NonEmpty as NE
import qualified Data.Map as Map
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import System.Console.GetOpt (
    ArgDescr (..),
    ArgOrder (..),
    OptDescr (..),
    getOpt,
    usageInfo,
 )
import System.Environment (getArgs)
import System.Exit (exitFailure)

import DNS.Do53.Client (
    LookupConf (..),
    LookupEnv,
    Seeds (..),
    defaultCacheConf,
    defaultLookupConf,
    withLookupConf,
 )
import DNS.Do53.Internal (
    NameTag (..),
    Reply (..),
    ResolveActions (..),
    ResolveInfo (..),
    Resolver,
 )
import DNS.DoX.Client (
    SVCBInfo (..),
    lookupSVCBInfo,
    modifyForDDR,
    toPipelineResolver,
 )
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (addResourceDataForSVCB)
import DNS.Types (
    DNSError (..),
    DNSMessage (..),
    Domain,
    Question (..),
    ResourceRecord (..),
    runInitIO,
    toRepresentation,
 )
import DNS.Types.Decode (decode)
import DNS.Types.Encode (encode)

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

----------------------------------------------------------------

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

----------------------------------------------------------------

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

pprDomain :: Domain -> String
pprDomain = init . toRepresentation

pprRR :: ResourceRecord -> String
pprRR ResourceRecord{..} = pprDomain rrname ++ " " ++ show rrtype ++ " " ++ show rdata

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
    unsafeHead [] = error "unsafeHead"
    unsafeHead (x : _) = x
    loop = do
        printDebug opts "Waiting..."
        wait <- waitReadSocketSTM s
        atomically wait
        printDebug opts "Waiting...done"
        mPiplineResolver <- selectSVCB <$> lookupSVCBInfo env
        case mPiplineResolver of
            Nothing -> printDebug opts "SVCB RR is not available"
            Just si -> do
                let ri = unsafeHead $ svcbInfoResolveInfos si
                printDebug opts $
                    "Running a pipeline resolver on " ++ show (svcbInfoALPN si) ++ " " ++ show (rinfoIP ri) ++ " " ++ show (rinfoPort ri)
                let piplineResolver = unsafeHead $ toPipelineResolver si
                piplineResolver (serverLoop opts s) `E.catch` ignore
        loop
    ignore (E.SomeException se) = printDebug opts $ show se

serverLoop :: Options -> Socket -> Resolver -> IO ()
serverLoop opts s resolver = loop
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

----------------------------------------------------------------

selectSVCB :: Either DNSError [[SVCBInfo]] -> Maybe SVCBInfo
selectSVCB (Right ((si : _) : _)) = Just $ modifyForDDR si
selectSVCB _ = Nothing

----------------------------------------------------------------

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
                , ractionValidate = True
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
