{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.Pipeline where

-- GHC packages

import Control.Concurrent.STM
import Control.Monad (forever, void)
import Data.ByteString (ByteString)

-- dnsext-* packages
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.TAP.Schema as DNSTAP
import DNS.Types (DNSFlags (..), DNSMessage (..), Question (..), RCODE (..), defaultResponse)
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import DNS.Types.Time

-- other packages
import Control.Monad (replicateM, when)
import Network.Socket (SockAddr)
import UnliftIO (SomeException (..), catch, handle, throwIO)

-- this package

import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Query (CacheResult (..), getResponseCached, getResponseIterative)
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats

----------------------------------------------------------------

--                          <------ Pipeline ----->
--
--                                       Iterative IO
--                                         Req Resp
--                            cache         ^   |
--                              |           |   v
--        +--------+ shared +--------+    +--------+    +--------+
-- Req -> | recver | -----> | cacher | -> | worker | -> | sender | -> Resp
--        +--------+ or any +--------|    +--------+    +--------+
--                               |                          ^
--                               +--------------------------+
--                                        Cache hit
--

----------------------------------------------------------------

mkPipeline :: Env -> Int -> Int -> IO ([IO ()], ToCacher)
mkPipeline env n workers = do
    qr <- newTQueueIO
    let toCacher = atomically . writeTQueue qr
        fromReceiver = atomically $ readTQueue qr
    let onePipeline = do
            qw <- newTQueueIO
            let toWorker = atomically . writeTQueue qw
                fromCacher = atomically $ readTQueue qw
            let mkCacher = cacherLogic env fromReceiver toWorker
                mkWorker = workerLogic env fromCacher
            return $ mkCacher : replicate workers mkWorker
    mks <- concat <$> replicateM n onePipeline
    return (mks, toCacher)

----------------------------------------------------------------

cacherLogic :: Env -> IO Fuel -> (Fuel -> IO ()) -> IO ()
cacherLogic env fromReceiver toWorker = handledLoop env "cacher" $ do
    fuel@Fuel{..} <- fromReceiver
    mx <- getResponseCached env fuelQuery
    case mx of
        None -> toWorker fuel
        Positive replyMsg -> do
            incStats (stats_ env) CacheHit
            fuelToSender fuel{fuelReply = replyMsg}
        Negative _replyErr -> cacheFailed env fuel

----------------------------------------------------------------

workerLogic :: Env -> IO Fuel -> IO ()
workerLogic env fromCacher = handledLoop env "worker" $ do
    fuel@Fuel{..} <- fromCacher
    ex <- getResponseIterative env fuelQuery
    case ex of
        Right replyMsg -> do
            incStats (stats_ env) CacheMiss
            fuelToSender fuel{fuelReply = replyMsg}
        Left _e -> cacheFailed env fuel

----------------------------------------------------------------

cacheFailed :: Env -> Fuel -> IO ()
cacheFailed env fuel@Fuel{..} = do
    let replyMsg =
            fuelQuery
                { flags = (flags fuelQuery){isResponse = True}
                , rcode = FormatErr
                }
    incStats (stats_ env) CacheFailed
    fuelToSender fuel{fuelReply = replyMsg}

----------------------------------------------------------------

record
    :: Env
    -> Fuel
    -> ByteString
    -> IO ()
record env Fuel{..} rspWire = do
    (s, ns) <- getCurrentTimeNsec
    let peersa = peerSockAddr fuelPeerInfo
    logDNSTAP_ env $ DNSTAP.composeMessage fuelProto fuelMysa peersa s ns rspWire
    let st = stats_ env
        Question{..} = head $ question fuelQuery
        DNSFlags{..} = flags fuelReply
    incStatsM st fromQueryTypes qtype (Just QueryTypeOther)
    incStatsM st fromDNSClass qclass (Just DNSClassOther)
    let rc = rcode fuelReply
    incStatsM st fromRcode rc Nothing
    when (rc == NoErr) $
        if answer fuelReply == []
            then incStats st RcodeNoData
            else incStats st RcodeNoError
    when authAnswer $ incStats st FlagAA
    when authenData $ incStats st FlagAD
    when chkDisable $ incStats st FlagCD
    when isResponse $ incStats st FlagQR
    when recAvailable $ incStats st FlagRA
    when recDesired $ incStats st FlagRD
    when trunCation $ incStats st FlagTC

----------------------------------------------------------------

type Recv = IO (ByteString, PeerInfo)
type Send = ByteString -> PeerInfo -> IO ()

receiverLogic
    :: Env -> SockAddr -> Recv -> ToCacher -> (Fuel -> IO ()) -> SocketProtocol -> IO ()
receiverLogic env mysa recv toCacher toSender proto =
    handledLoop env "receiverUDP" $ void $ receiverLogic' env mysa recv toCacher toSender proto

receiverLogicVC
    :: Env -> SockAddr -> Recv -> ToCacher -> (Fuel -> IO ()) -> SocketProtocol -> IO ()
receiverLogicVC env mysa recv toCacher toSender proto = go
  where
    go = do
        -- fixme: error logging
        cont <- receiverLogic' env mysa recv toCacher toSender proto
        when cont go

receiverLogic'
    :: Env -> SockAddr -> Recv -> ToCacher -> (Fuel -> IO ()) -> SocketProtocol -> IO Bool
receiverLogic' env mysa recv toCacher toSender proto = do
    (bs, peerInfo) <- recv
    if bs == ""
        then return False
        else do
            case DNS.decode bs of
                Right queryMsg -> do
                    let fuel = Fuel queryMsg defaultResponse mysa peerInfo proto toSender
                    toCacher fuel
                Left e -> do
                    logLn env Log.WARN $ "decode-error: " ++ show e
            return True

senderLogic :: Env -> Send -> FromX -> IO ()
senderLogic env send fromX =
    handledLoop env "senderUDP" $ senderLogic' env send fromX

senderLogicVC :: Env -> Send -> FromX -> IO ()
senderLogicVC env send fromX =
    breakableLoop env "senderVC" $ senderLogic' env send fromX

senderLogic' :: Env -> Send -> IO Fuel -> IO ()
senderLogic' env send fromX = do
    fuel <- fromX
    let bs = DNS.encode $ fuelReply fuel
    send bs $ fuelPeerInfo fuel
    record env fuel bs

----------------------------------------------------------------

logLn :: Env -> Log.Level -> String -> IO ()
logLn env level = logLines_ env level Nothing . (: [])

----------------------------------------------------------------

handledLoop :: Env -> String -> IO () -> IO ()
handledLoop env tag body = forever $ handle onError body
  where
    onError (SomeException e) = logLn env Log.WARN (tag ++ ": " ++ show e)

breakableLoop :: Env -> String -> IO () -> IO ()
breakableLoop env tag body = forever body `catch` onError
  where
    onError (SomeException e) = do
        logLn env Log.WARN (tag ++ ": " ++ show e)
        throwIO e

----------------------------------------------------------------

mkConnector :: IO (Fuel -> IO (), FromX)
mkConnector = do
    qs <- newTQueueIO
    let toSender = atomically . writeTQueue qs
        fromX = atomically $ readTQueue qs
    return (toSender, fromX)
