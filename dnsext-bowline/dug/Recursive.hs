{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Recursive (recursiveQuery) where

import Codec.Serialise
import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Concurrent.STM
import qualified Control.Exception as E
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
    NameTag (..),
    PipelineResolver,
    Reply (..),
    ResolveActions (..),
    ResolveInfo (..),
    defaultResolveActions,
    defaultResolveInfo,
    resolve,
 )
import DNS.DoX.Client
import qualified DNS.Log as Log
import DNS.Types (Question (..))
import qualified DNS.Types as DNS
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as BL
import Data.Either
import Data.IP (IP (..))
import qualified Data.List as List
import qualified Network.QUIC.Client as QUIC
import Network.Socket (HostName, PortNumber)
import qualified Network.TLS as TLS
import System.Console.ANSI.Types
import System.Directory (doesFileExist, removeFile)
import System.Exit (exitFailure)
import System.Random (randomRIO)

import Types

recursiveQuery
    :: [(IP, Maybe HostName)]
    -> PortNumber
    -> (DNS.DNSMessage -> STM ())
    -> Log.PutLines STM
    -> [(Question, QueryControls)]
    -> Options
    -> TQueue (NameTag, String)
    -> IO ()
recursiveQuery ips port putLnSTM putLinesSTM qcs opt@Options{..} tq = do
    let ractions =
            defaultResolveActions
                { ractionLog = \a b c -> atomically $ putLinesSTM a b c
                , ractionOnResumptionInfo = case optResumptionFile of
                    Nothing -> \_ _ -> return ()
                    Just file -> saveResumption file tq
                , ractionUseEarlyData = opt0RTT
                , ractionKeyLog = case optKeyLogFile of
                    Nothing -> \_ -> return ()
                    Just file -> \msg -> safeAppendFile file (C8.pack (msg ++ "\n"))
                , ractionValidate = optValidate
                }
    (conf, aps) <- getCustomConf ips port mempty opt ractions
    mx <-
        if optDoX == "auto"
            then resolvePipeline conf
            else case makePersistentResolver optDoX of
                -- PersistentResolver
                Just persitResolver -> do
                    mrs <- case optResumptionFile of
                        Nothing -> return []
                        Just file -> do
                            exist <- doesFileExist file
                            if exist
                                then do
                                    ct <- loadResumption file
                                    removeFile file
                                    return ct
                                else return []
                    let ris = makeResolveInfo ractions tq aps mrs
                    -- [PipelineResolver]
                    return $ Just (persitResolver <$> ris)
                Nothing -> return Nothing
    case mx of
        Nothing -> withLookupConf conf $ \LookupEnv{..} -> do
            -- UDP
            let printIt (q, ctl) = resolve lenvResolveEnv q ctl >>= atomically . printReplySTM putLnSTM putLinesSTM
            mapM_ printIt qcs
        Just [] -> do
            putStrLn $ show optDoX ++ " connection cannot be created"
            exitFailure
        Just pipes -> do
            -- VC
            let len = length qcs
            refs <- replicateM len $ newTVarIO False
            let targets = zip qcs refs
            -- raceAny cannot be used to ensure that TLS sessino tickets
            -- are certainly saved.
            mapConcurrently_ (resolver putLnSTM putLinesSTM targets) pipes

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
    :: (DNS.DNSMessage -> STM ())
    -> Log.PutLines STM
    -> [((Question, QueryControls), TVar Bool)]
    -> PipelineResolver
    -> IO ()
resolver putLnSTM putLinesSTM targets pipeline = pipeline $ \resolv ->
    -- running concurrently for multiple target domains
    mapConcurrently_ (printIt resolv) targets
  where
    printIt resolv ((q, ctl), tvar) = do
        er <- resolv q ctl
        atomically $ do
            done <- readTVar tvar
            unless done $ do
                printReplySTM putLnSTM putLinesSTM er
                writeTVar tvar True

printReplySTM
    :: (DNS.DNSMessage -> STM ())
    -> Log.PutLines STM
    -> Either DNS.DNSError Reply
    -> STM ()
printReplySTM _ putLinesSTM (Left err) = putLinesSTM Log.WARN (Just Red) [show err]
printReplySTM putLnSTM putLinesSTM (Right r@Reply{..}) = do
    let h = mkHeader r
    putLinesSTM Log.WARN (Just Green) [h]
    putLnSTM replyDNSMessage

makeResolveInfo
    :: ResolveActions
    -> TQueue (NameTag, String)
    -> [(IP, Maybe HostName, PortNumber)]
    -> [(NameTag, ByteString)]
    -> [ResolveInfo]
makeResolveInfo ractions tq aps ss = mk <$> aps
  where
    mk (ip, msvr, port) =
        defaultResolveInfo
            { rinfoIP = ip
            , rinfoPort = port
            , rinfoUDPRetry = 2
            , rinfoActions = ractions'
            , rinfoVCLimit = 8192
            , rinfoServerName = msvr
            }
      where
        ractions' =
            ractions
                { ractionOnConnectionInfo = \tag info -> atomically $ writeTQueue tq (tag, info)
                , ractionResumptionInfo = \tag -> map snd $ fst $ List.partition (\(t, _) -> t == tag) ss
                }

{- FOURMOLU_DISABLE -}
getCustomConf
    :: [(IP, Maybe HostName)]
    -> PortNumber
    -> QueryControls
    -> Options
    -> ResolveActions
    -> IO (LookupConf, [(IP, Maybe HostName, PortNumber)])
getCustomConf ips port ctl Options{..} ractions = case ips of
    [] -> return (conf, [])
    hs -> do
        let ahs = if optDisableV6NS then [ip4 | ip4@(IPv4{}, _) <- hs] else hs
            ahps = map (\(x,y) -> (x,y,port)) ahs
            aps = map (\(x,_) -> (x,port)) ahs
        return (conf{lconfSeeds = SeedsAddrPorts aps}, ahps)
  where
    conf =
        DNS.defaultLookupConf
            { lconfUDPRetry = 2
            , lconfQueryControls = ctl
            , lconfConcurrent = True
            , lconfActions = ractions
            }
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

mkHeader :: Reply -> String
mkHeader Reply{..} =
    ";; "
        ++ unNameTag replyTag
        ++ ", Tx:"
        ++ show replyTxBytes
        ++ "bytes"
        ++ ", Rx:"
        ++ show replyRxBytes
        ++ "bytes"

----------------------------------------------------------------

saveResumption :: FilePath -> TQueue (NameTag, String) -> NameTag -> ByteString -> IO ()
saveResumption file tq name@(NameTag tag) bs = do
    case extractInfo of
        Nothing -> return ()
        Just info -> atomically $ writeTQueue tq (name, info)
    safeAppendFile file (C8.pack tag <> " " <> BS16.encode bs <> "\n")
  where
    extractInfo
        | "QUIC" `List.isSuffixOf` tag || "H3" `List.isSuffixOf` tag =
            case deserialiseOrFail $ BL.fromStrict bs of
                Left _ -> Nothing
                Right (info :: QUIC.ResumptionInfo) ->
                    Just $ next (QUIC.isResumptionPossible info) (QUIC.is0RTTPossible info)
        | otherwise =
            case deserialiseOrFail $ BL.fromStrict bs of
                Left _ -> Nothing
                Right (_ :: TLS.SessionID, sd :: TLS.SessionData) ->
                    Just $ next True (TLS.is0RTTPossible sd)
    next res rtt0 = "Next(Resumption:" ++ ok res ++ ", 0-RTT:" ++ ok rtt0 ++ ")"
    ok True = "OK"
    ok False = "NG"

loadResumption :: FilePath -> IO [(NameTag, ByteString)]
loadResumption file = map toKV . C8.lines <$> C8.readFile file
  where
    toKV l = (NameTag $ C8.unpack k, fromRight "" $ BS16.decode $ C8.drop 1 v)
      where
        (k, v) = BS.break (== 32) l

safeAppendFile :: FilePath -> ByteString -> IO ()
safeAppendFile file bs = loop (10 :: Int)
  where
    loop 0 = putStrLn "appendFile failed"
    loop n = do
        ex <- E.try (BS.appendFile file bs)
        case ex of
            Right () -> return ()
            Left (E.SomeException _) -> do
                r <- randomRIO (1, 10)
                threadDelay (r * 1000)
                loop (n - 1)
