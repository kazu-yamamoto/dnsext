{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.Pipeline where

-- GHC packages
import GHC.Event (TimerManager, TimeoutKey, getSystemTimerManager, registerTimeout, updateTimeout)
import Control.Concurrent (threadWaitReadSTM)
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.IntSet as Set
import System.Posix.Types (Fd (..))

-- libs
import UnliftIO.Exception (SomeException (..), catch, handle, throwIO)

-- dnsext packages
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.TAP.Schema as DNSTAP
import DNS.Types (DNSFlags (..), DNSMessage (..), EDNS (..), EDNSheader (..), Question (..), RCODE (..))
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import DNS.Types.Time

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Query (CacheResult (..), getResponseCached, getResponseIterative)
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.WorkerStats
import DNS.Iterative.Stats

----------------------------------------------------------------

getWorkerStats :: Int -> IO [WorkerStatOP]
getWorkerStats workersN = replicateM workersN getWorkerStatOP

----------------------------------------------------------------

-- |
-- @
--                          |------ Pipeline ------|
--
--                                       Iterative IO
--                                         Req Resp
--                  ToCacher  cache         ^   |
--                              |           |   v
--        +--------+ shared +--------+    +--------+    +--------+
-- Req -> | recver | -----> | cacher | -> | worker | -> | sender | -> Resp
--        +--------+ or any +--------|    +--------+    +--------+
--                               |                          ^
--                               +--------------------------+
--                                        Cache hit
--                 Input BS       Input Msg        Output
-- @
mkPipeline
    :: Env
    -> Int
    -- ^ The number of cashers
    -> Int
    -- ^ The number of workers
    -> [WorkerStatOP]
    -> IO ([IO ()], [IO ()], ToCacher)
    -- ^ (worker actions, cacher actions, input to cacher)
mkPipeline env cachersN _workersN workerStats = do
    qr <- newTQueueIO
    let toCacher = atomically . writeTQueue qr
        fromReceiver = atomically $ readTQueue qr
    qw <- newTQueueIO
    let toWorker = atomically . writeTQueue qw
        fromCacher = atomically $ readTQueue qw
    let cachers = replicate cachersN $ cacherLogic env fromReceiver toWorker
    let workers = [workerLogic env wstat fromCacher | wstat <- workerStats]
    return (cachers, workers, toCacher)

----------------------------------------------------------------

cacherLogic :: Env -> FromReceiver -> ToWorker -> IO ()
cacherLogic env fromReceiver toWorker = handledLoop env "cacher" $ do
    inpBS@Input{..} <- fromReceiver
    case DNS.decode inputQuery of
        Left e -> logLn env Log.WARN $ "decode-error: " ++ show e
        Right queryMsg -> do
            -- Input ByteString -> Input DNSMessage
            let inp = inpBS{inputQuery = queryMsg}
            mx <- getResponseCached env queryMsg
            case mx of
                CResultMissHit -> toWorker inp
                CResultHit replyMsg -> do
                    mapM_ (incStats $ stats_ env) [CacheHit, QueriesAll]
                    let bs = DNS.encode replyMsg
                    record env inp replyMsg bs
                    inputToSender $ Output bs inputRequestNum inputPeerInfo
                CResultDenied _replyErr -> logicDenied env inp

----------------------------------------------------------------

workerLogic :: Env -> WorkerStatOP -> FromCacher -> IO ()
workerLogic env WorkerStatOP{..} fromCacher = handledLoop env "worker" $ do
    setWorkerStat WWaitDequeue
    inp@Input{..} <- fromCacher
    case question inputQuery of
        q : _ -> setWorkerStat (WRun q)
        [] -> pure ()
    ex <- getResponseIterative env inputQuery
    setWorkerStat WWaitEnqueue
    case ex of
        Right replyMsg -> do
            mapM_ (incStats $ stats_ env) [CacheMiss, QueriesAll]
            let bs = DNS.encode replyMsg
            record env inp replyMsg bs
            inputToSender $ Output bs inputRequestNum inputPeerInfo
        Left _e -> logicDenied env inp

----------------------------------------------------------------

logicDenied :: Env -> Input DNSMessage -> IO ()
logicDenied env _inp@Input{} = do
    mapM_ (incStats $ stats_ env) [ResolveDenied, QueriesAll]

{- {- not reply for deny case. -}
let replyMsg =
        inputQuery
            { flags = (flags inputQuery){isResponse = True}
            , rcode = FormatErr
            }
let bs = DNS.encode replyMsg
record env inp replyMsg bs
inputToSender $ Output bs inputPeerInfo
 -}

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
    case ednsHeader inputQuery of
        EDNSheader (EDNS{..})
            | ednsDnssecOk -> incStats st QueryDO
        _ -> pure ()
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

type MkInput = ByteString -> PeerInfo -> Int -> Input ByteString

mkInput :: SockAddr -> ToSender -> SocketProtocol -> MkInput
mkInput mysa toSender proto bs peerInfo i = Input bs i mysa peerInfo proto toSender

{- FOURMOLU_DISABLE -}
receiverVC
    :: String -> Env -> VcSession
    -> Recv -> ToCacher -> MkInput -> IO VcFinished
receiverVC name env vcs@VcSession{..} recv toCacher mkInput_ = loop 1 `E.catch` onError
  where
    onError se@(SomeException e) = warnOnError env name se *> throwIO e
    loop i = casesRecv $ \bs peerInfo -> step i bs peerInfo *> loop (succ i)
      where
        caseEof = atomically (enableVcEof vcEof_) $> VfEof
        casesRecv caseNext = cases =<< waitVcInput vcs
          where
            cases timeout
                | timeout     = pure VfTimeout
                | otherwise   = do
                      (bs, peerInfo) <- recv
                      casesSize (BS.length bs) bs peerInfo
            casesSize sz bs peerInfo
                | sz == 0                 = resetVcTimeout vcTimeout_ *> caseEof
                | sz > vcSlowlorisSize_   = resetVcTimeout vcTimeout_ *> caseNext bs peerInfo
                | otherwise               =                              caseNext bs peerInfo

    step i bs peerInfo = do
        atomically (addVcPending vcPendings_ i)
        toCacher $ mkInput_ bs peerInfo i
{- FOURMOLU_ENABLE -}

receiverLogic
    :: Env -> SockAddr -> Recv -> ToCacher -> ToSender -> SocketProtocol -> IO ()
receiverLogic env mysa recv toCacher toSender proto =
    handledLoop env "receiverUDP" $ void $ receiverLogic' mysa recv toCacher toSender proto

receiverLogic'
    :: SockAddr -> Recv -> ToCacher -> ToSender -> SocketProtocol -> IO Bool
receiverLogic' mysa recv toCacher toSender proto = do
    (bs, peerInfo) <- recv
    if bs == ""
        then return False
        else do
            toCacher $ Input bs 0 mysa peerInfo proto toSender
            return True

{- FOURMOLU_DISABLE -}
senderVC
    :: String -> Env -> VcSession
    -> Send -> FromX -> IO VcFinished
senderVC name env vcs@VcSession{..} send fromX = loop `E.catch` onError
  where
    -- logging async exception intentionally, for not expected `cancel`
    onError se@(SomeException e) = warnOnError env name se *> throwIO e
    loop = maybe (step *> loop) pure =<< waitVcOutput vcs
    step = do
        let body (Output bs _ peerInfo) = resetVcTimeout vcTimeout_ *> send bs peerInfo
            finalize (Output _ i _) = atomically (delVcPending vcPendings_ i)
        E.bracket fromX finalize body
{- FOURMOLU_ENABLE -}

senderLogic :: Env -> Send -> FromX -> IO ()
senderLogic env send fromX =
    handledLoop env "senderUDP" $ senderLogic' send fromX

senderLogic' :: Send -> FromX -> IO ()
senderLogic' send fromX = do
    Output bs _ peerInfo <- fromX
    send bs peerInfo

----------------------------------------------------------------

type VcEof = TVar Bool
type VcWaitRead = STM ()
type VcPendings = TVar Set.IntSet
type VcRespAvail = STM Bool

{- FOURMOLU_DISABLE -}
data VcTimeout =
    VcTimeout
    { vtManager_        :: TimerManager
    , vtKey_            :: TimeoutKey
    , vtState_          :: TVar Bool
    , vtMicrosec_       :: Int
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data VcSession =
    VcSession
    { vcEof_            :: VcEof
    , vcPendings_       :: VcPendings
    , vcRespAvail_      :: VcRespAvail
    , vcWaitRead_       :: IO VcWaitRead
    , vcTimeout_        :: VcTimeout
    , vcSlowlorisSize_  :: Int
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data VcFinished
    = VfEof
    | VfTimeout
    deriving (Eq, Show)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
initVcTimeout :: Int -> IO VcTimeout
initVcTimeout micro = do
    st  <- newTVarIO False
    mgr <- getSystemTimerManager
    key <- registerTimeout mgr micro (atomically $ writeTVar st True)
    pure $ VcTimeout mgr key st micro
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
initVcSession :: IO VcWaitRead -> Int -> Int -> IO (VcSession, ToSender, FromX)
initVcSession getWaitIn micro slsize = do
    vcEof       <- newTVarIO False
    vcPendinfs  <- newTVarIO Set.empty
    senderQ     <- newTQueueIO
    vcTimeout   <- initVcTimeout micro
    let toSender = atomically . writeTQueue senderQ
        fromX = atomically $ readTQueue senderQ
    pure (VcSession vcEof vcPendinfs (not <$> isEmptyTQueue senderQ) getWaitIn vcTimeout slsize, toSender, fromX)
{- FOURMOLU_ENABLE -}

enableVcEof :: VcEof -> STM ()
enableVcEof eof = writeTVar eof True

addVcPending :: VcPendings -> Int -> STM ()
addVcPending pendings i = modifyTVar' pendings (Set.insert i)

delVcPending :: VcPendings -> Int -> STM ()
delVcPending pendings i = modifyTVar' pendings (Set.delete i)

resetVcTimeout :: VcTimeout -> IO ()
resetVcTimeout VcTimeout{..} = updateTimeout vtManager_ vtKey_ vtMicrosec_

waitVcInput :: VcSession -> IO Bool
waitVcInput VcSession{vcTimeout_=VcTimeout{..},..} = do
    waitIn <- vcWaitRead_
    atomically $ do
        timeout <- readTVar vtState_
        when (not timeout) waitIn $> timeout

{- FOURMOLU_DISABLE -}
--   eof       pending     timeout   avail       sender-loop
--
--   eof       null        to        no-avail    break
--   not-eof   null        to        no-avail    break
--   eof       null        not-to    no-avail    break
--   not-eof   null        not-to    no-avail    wait
--   -         not-null    -         no-avail    wait
--   -         -                     avail       loop
waitVcOutput :: VcSession -> IO (Maybe VcFinished)
waitVcOutput VcSession{vcTimeout_=VcTimeout{..},..} = atomically $ do
    mayEof  <- (VfEof     <$) . guard <$> readTVar vcEof_
    mayTo   <- (VfTimeout <$) . guard <$> readTVar vtState_
    avail <- vcRespAvail_
    maybe (guard avail $> Nothing) (eoVC avail) $ mayEof <|> mayTo
  where
    eoVC avail fc
        | avail      = pure Nothing
        | otherwise  = (Just fc <$) . guard . Set.null =<< readTVar vcPendings_
{- FOURMOLU_ENABLE -}

mkConnector :: IO (ToSender, FromX, VcRespAvail)
mkConnector = do
    qs <- newTQueueIO
    let toSender = atomically . writeTQueue qs
        fromX = atomically $ readTQueue qs
    return (toSender, fromX, not <$> isEmptyTQueue qs)

----------------------------------------------------------------

waitReadSocketSTM' :: Socket -> IO (STM ())
waitReadSocketSTM' s = fst <$> waitReadSocketSTM s

waitReadSocketSTM :: Socket -> IO (STM (), IO ())
waitReadSocketSTM s = withFdSocket s $ threadWaitReadSTM . Fd

----------------------------------------------------------------

handledLoop :: Env -> String -> IO () -> IO ()
handledLoop env tag body = forever $ handle (warnOnError env tag) body

breakableLoop :: Env -> String -> IO () -> IO ()
breakableLoop env tag body = forever body `catch` onError
  where
    onError se@(SomeException e) = warnOnError env tag se *> throwIO e

warnOnError :: Env -> String -> SomeException -> IO ()
warnOnError env tag (SomeException e) = logLn env Log.WARN (tag ++ ": exception: " ++ show e)

----------------------------------------------------------------

logLn :: Env -> Log.Level -> String -> IO ()
logLn env level = logLines_ env level Nothing . (: [])
