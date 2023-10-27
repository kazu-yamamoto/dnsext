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
import DNS.Types (DNSFlags (..), DNSMessage (..), Question (..), RCODE (..))
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
--                 Input BS       Input Msg        Output

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

cacherLogic :: Env -> FromReciver -> ToWorker -> IO ()
cacherLogic env fromReceiver toWorker = handledLoop env "cacher" $ do
    inpBS@Input{..} <- fromReceiver
    case DNS.decode inputQuery of
        Left e -> logLn env Log.WARN $ "decode-error: " ++ show e
        Right queryMsg -> do
            -- Input ByteString -> Input DNSMessage
            let inp = inpBS { inputQuery = queryMsg }
            mx <- getResponseCached env queryMsg
            case mx of
                None -> toWorker inp
                Positive replyMsg -> do
                    incStats (stats_ env) CacheHit
                    let bs = DNS.encode replyMsg
                    record env inp replyMsg bs
                    inputToSender $ Output bs inputPeerInfo
                Negative _replyErr -> cacheFailed env inp

----------------------------------------------------------------

workerLogic :: Env -> FromCacher -> IO ()
workerLogic env fromCacher = handledLoop env "worker" $ do
    inp@Input{..} <- fromCacher
    ex <- getResponseIterative env inputQuery
    case ex of
        Right replyMsg -> do
            incStats (stats_ env) CacheMiss
            let bs = DNS.encode replyMsg
            record env inp replyMsg bs
            inputToSender $ Output bs inputPeerInfo
        Left _e -> cacheFailed env inp

----------------------------------------------------------------

cacheFailed :: Env -> Input DNSMessage -> IO ()
cacheFailed env inp@Input{..} = do
    let replyMsg =
            inputQuery
                { flags = (flags inputQuery){isResponse = True}
                , rcode = FormatErr
                }
    incStats (stats_ env) CacheFailed
    let bs = DNS.encode replyMsg
    record env inp replyMsg bs
    inputToSender $ Output bs inputPeerInfo

----------------------------------------------------------------

record
    :: Env
    -> Input DNSMessage
    -> DNSMessage
    -> ByteString
    -> IO ()
record env Input{..} reply rspWire = do
    (s, ns) <- getCurrentTimeNsec
    let peersa = peerSockAddr inputPeerInfo
    logDNSTAP_ env $ DNSTAP.composeMessage inputProto inputMysa peersa s ns rspWire
    let st = stats_ env
        Question{..} = head $ question inputQuery
        DNSFlags{..} = flags reply
    incStatsM st fromQueryTypes qtype (Just QueryTypeOther)
    incStatsM st fromDNSClass qclass (Just DNSClassOther)
    let rc = rcode reply
    incStatsM st fromRcode rc Nothing
    when (rc == NoErr) $
        if answer reply == []
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
    :: Env -> SockAddr -> Recv -> ToCacher -> ToSender -> SocketProtocol -> IO ()
receiverLogic env mysa recv toCacher toSender proto =
    handledLoop env "receiverUDP" $ void $ receiverLogic' mysa recv toCacher toSender proto

receiverLogicVC
    :: Env -> SockAddr -> Recv -> ToCacher -> ToSender -> SocketProtocol -> IO ()
receiverLogicVC _env mysa recv toCacher toSender proto = go
  where
    go = do
        cont <- receiverLogic' mysa recv toCacher toSender proto
        when cont go

receiverLogic'
    :: SockAddr -> Recv -> ToCacher -> ToSender -> SocketProtocol -> IO Bool
receiverLogic' mysa recv toCacher toSender proto = do
    (bs, peerInfo) <- recv
    if bs == ""
        then return False
        else do
            toCacher $ Input bs mysa peerInfo proto toSender
            return True

senderLogic :: Env -> Send -> FromX -> IO ()
senderLogic env send fromX =
    handledLoop env "senderUDP" $ senderLogic' send fromX

senderLogicVC :: Env -> Send -> FromX -> IO ()
senderLogicVC env send fromX =
    breakableLoop env "senderVC" $ senderLogic' send fromX

senderLogic' :: Send -> FromX -> IO ()
senderLogic' send fromX = do
    Output bs peerInfo <- fromX
    send bs peerInfo

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

mkConnector :: IO (ToSender, FromX)
mkConnector = do
    qs <- newTQueueIO
    let toSender = atomically . writeTQueue qs
        fromX = atomically $ readTQueue qs
    return (toSender, fromX)
