{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Recursive (recursiveQeury) where

import Control.Concurrent
import Control.Concurrent.Async
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
    ResolveInfo (..),
    Result (..),
    defaultResolveInfo,
    resolve,
 )
import DNS.DoX.Client
import qualified DNS.Log as Log
import DNS.Types (Question (..))
import qualified DNS.Types as DNS
import Data.ByteString.Short (ShortByteString)
import Data.Either
import Data.IORef
import Data.IP (IP, IPv4, IPv6)
import Data.String
import Network.Socket (HostName, PortNumber)
import System.Console.ANSI.Types
import System.Exit (exitFailure)
import Text.Read (readMaybe)

recursiveQeury
    :: [HostName]
    -> PortNumber
    -> ShortByteString
    -> (DNS.DNSMessage -> IO ())
    -> Log.PutLines
    -> [DNS.ResolveActionsFlag]
    -> [(Question, QueryControls)]
    -> IO ()
recursiveQeury mserver port dox putLn putLines raflags qcs = do
    conf <- getCustomConf mserver port mempty putLines raflags
    mx <-
        if dox == "auto"
            then resolvePipeline conf
            else case makePersistentResolver dox of
                Just r -> do
                    let ris = makeResolveInfo putLines raflags port <$> (read <$> mserver)
                    return $ Just (r <$> ris)
                Nothing -> return Nothing
    case mx of
        Nothing -> withLookupConf conf $ \LookupEnv{..} -> do
            let printIt (q, ctl) = resolve lenvResolveEnv q ctl >>= printResult putLn putLines
            mapM_ printIt qcs
        Just [] -> do
            putStrLn "No proper SVCB"
            exitFailure
        Just pipes -> do
            let len = length qcs
            refs <- replicateM len $ newIORef False
            let targets = zip qcs refs
            stdoutLock <- newMVar ()
            foldr1 concurrently_ $ map (resolver stdoutLock putLn putLines targets) pipes

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
    foldr1 concurrently_ $ map (printIt resolv) targets
  where
    printIt resolv ((q, ctl), ref) = do
        er <- resolv q ctl
        notyet <- atomicModifyIORef' ref (True,)
        unless notyet $ withMVar stdoutLock $ \() ->
            printResult putLn putLines er

printResult
    :: (DNS.DNSMessage -> IO ())
    -> Log.PutLines
    -> Either DNS.DNSError Result
    -> IO ()
printResult _ _ (Left err) = print err
printResult putLn putLines (Right r@Result{..}) = do
    let h = mkHeader r
    putLines Log.WARN (Just Green) [h]
    let Reply{..} = resultReply
    putLn replyDNSMessage

makeResolveInfo
    :: Log.PutLines
    -> [DNS.ResolveActionsFlag]
    -> PortNumber
    -> IP
    -> ResolveInfo
makeResolveInfo putLines raflags port ip =
    defaultResolveInfo
        { rinfoIP = ip
        , rinfoPort = port
        , rinfoUDPRetry = 2
        , rinfoActions =
            DNS.defaultResolveActions
                { ractionLog = putLines
                , ractionFlags = raflags
                }
        }

getCustomConf
    :: [HostName]
    -> PortNumber
    -> QueryControls
    -> Log.PutLines
    -> [DNS.ResolveActionsFlag]
    -> IO LookupConf
getCustomConf mserver port ctl putLines raflags = case mserver of
    [] -> return conf
    hs -> do
        as <- concat <$> mapM toNumeric hs
        let aps = map (\h -> (fromString h, port)) as
        return $ conf{lconfSeeds = SeedsAddrPorts aps}
  where
    conf =
        DNS.defaultLookupConf
            { lconfUDPRetry = 2
            , lconfQueryControls = ctl
            , lconfConcurrent = True
            , lconfActions =
                DNS.defaultResolveActions
                    { ractionLog = putLines
                    , ractionFlags = raflags
                    }
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
