{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Recursive (recursiveQuery) where

import Control.Concurrent
import Control.Monad
import DNS.Do53.Client (
    LookupConf (..),
    QueryControls,
    ResolveActions (..),
    Seeds (..),
    withLookupConf,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    LookupEnv (..),
    PipelineResolver,
    Reply (..),
    ResolveActions (..),
    ResolveInfo (..),
    Result (..),
    defaultResolveActions,
    defaultResolveInfo,
    raceAny,
    resolve,
 )
import DNS.DoX.Client
import qualified DNS.Log as Log
import DNS.Types (Question (..))
import qualified DNS.Types as DNS
import qualified Data.ByteString as BS
import Data.Either
import Data.IORef
import Data.IP (IP, IPv4, IPv6)
import Data.String
import Network.Socket (HostName, PortNumber)
import System.Console.ANSI.Types
import System.Directory (doesFileExist)
import System.Exit (exitFailure)
import Text.Read (readMaybe)

import Types

recursiveQuery
    :: [HostName]
    -> PortNumber
    -> (DNS.DNSMessage -> IO ())
    -> Log.PutLines
    -> [(Question, QueryControls)]
    -> Options
    -> IO ()
recursiveQuery mserver port putLn putLines qcs Options{..} = do
    mbs <- case optResumptionFile of
        Nothing -> return Nothing
        Just file -> do
            exist <- doesFileExist file
            if exist
                then Just <$> BS.readFile file
                else return Nothing
    let ractions =
            defaultResolveActions
                { ractionLog = putLines
                , ractionSaveResumption = case optResumptionFile of
                    Nothing -> \_ -> return ()
                    Just file -> BS.writeFile file
                , ractionUseEarlyData = opt0RTT
                , ractionResumptionInfo = mbs
                , ractionKeyLog = case optKeyLogFile of
                    Nothing -> \_ -> return ()
                    Just file -> \msg -> appendFile file (msg ++ "\n")
                }
    (conf, aps) <- getCustomConf mserver port mempty ractions
    mx <-
        if optDoX == "auto"
            then resolvePipeline conf
            else case makePersistentResolver optDoX of
                Just r -> do
                    let ris = makeResolveInfo ractions aps
                    return $ Just (r <$> ris)
                Nothing -> return Nothing
    stdoutLock <- newMVar ()
    case mx of
        Nothing -> withLookupConf conf $ \LookupEnv{..} -> do
            -- UDP
            let printIt (q, ctl) = resolve lenvResolveEnv q ctl >>= printResult stdoutLock putLn putLines
            mapM_ printIt qcs
        Just [] -> do
            putStrLn $ show optDoX ++ " connection cannot be created"
            exitFailure
        Just pipes -> do
            -- VC
            let len = length qcs
            refs <- replicateM len $ newIORef False
            let targets = zip qcs refs
            raceAny $ map (resolver stdoutLock putLn putLines targets) pipes

resolvePipeline :: LookupConf -> IO (Maybe [PipelineResolver])
resolvePipeline conf = do
    er <- withLookupConf conf lookupSVCBInfo
    case er of
        Left err -> do
            print err
            exitFailure
        Right si -> do
            let psss = map toPipelineResolvers si
            case psss of
                [] -> do
                    putStrLn "No proper SVCB"
                    exitFailure
                pss : _ -> case pss of
                    [] -> do
                        putStrLn "No proper SVCB"
                        exitFailure
                    ps : _ -> return $ Just ps

resolver
    :: MVar ()
    -> (DNS.DNSMessage -> IO ())
    -> Log.PutLines
    -> [((Question, QueryControls), IORef Bool)]
    -> PipelineResolver
    -> IO ()
resolver stdoutLock putLn putLines targets pipeline = pipeline $ \resolv ->
    raceAny $ map (printIt resolv) targets
  where
    printIt resolv ((q, ctl), ref) = do
        er <- resolv q ctl
        notyet <- atomicModifyIORef' ref (True,)
        unless notyet $ printResult stdoutLock putLn putLines er

printResult
    :: MVar ()
    -> (DNS.DNSMessage -> IO ())
    -> Log.PutLines
    -> Either DNS.DNSError Result
    -> IO ()
printResult _ _ _ (Left err) = print err
printResult stdoutLock putLn putLines (Right r@Result{..}) =
    withMVar stdoutLock $ \() -> do
        let h = mkHeader r
        putLines Log.WARN (Just Green) [h]
        let Reply{..} = resultReply
        putLn replyDNSMessage

makeResolveInfo
    :: ResolveActions
    -> [(IP, PortNumber)]
    -> [ResolveInfo]
makeResolveInfo ractions aps = mk <$> aps
  where
    mk (ip, port) =
        defaultResolveInfo
            { rinfoIP = ip
            , rinfoPort = port
            , rinfoUDPRetry = 2
            , rinfoActions = ractions
            , rinfoVCLimit = 8192
            }

getCustomConf
    :: [HostName]
    -> PortNumber
    -> QueryControls
    -> ResolveActions
    -> IO (LookupConf, [(IP, PortNumber)])
getCustomConf mserver port ctl ractions = case mserver of
    [] -> return (conf, [])
    hs -> do
        as <- concat <$> mapM toNumeric hs
        let aps = map (\h -> (fromString h, port)) as
        return (conf{lconfSeeds = SeedsAddrPorts aps}, aps)
  where
    conf =
        DNS.defaultLookupConf
            { lconfUDPRetry = 2
            , lconfQueryControls = ctl
            , lconfConcurrent = True
            , lconfActions = ractions
            }

    toNumeric :: HostName -> IO [HostName]
    toNumeric sname | isNumeric sname = return [sname]
    toNumeric sname = DNS.withLookupConf DNS.defaultLookupConf $ \env -> do
        let dom = DNS.fromRepresentation sname
        eA <- fmap (fmap (show . DNS.a_ipv4)) <$> DNS.lookupA env dom
        eAAAA <- fmap (fmap (show . DNS.aaaa_ipv6)) <$> DNS.lookupAAAA env dom
        case rights [eA, eAAAA] of
            [] -> fail $ show eA
            hss -> return $ concat hss

isNumeric :: HostName -> Bool
isNumeric h = case readMaybe h :: Maybe IPv4 of
    Just _ -> True
    Nothing -> case readMaybe h :: Maybe IPv6 of
        Just _ -> True
        Nothing -> False

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
