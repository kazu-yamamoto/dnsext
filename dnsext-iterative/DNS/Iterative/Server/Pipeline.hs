{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.Pipeline (
    mkPipeline,
    mkConnector,
    mkInput,
    getWorkerStats,
    VcPendings,
    VcSession (..),
    initVcSession,
    waitVcInput,
    waitVcOutput,
    RxState (..),
    getRxState,
    setRxState,
    addVcPending,
    delVcPending,
    waitReadSocketSTM,
    waitReadSocketSTM',
    receiverVC,
    senderVC,
    senderLogic,
    receiverLogic,
    receiverLogic',
    logLn,
    retryUntil,
    Send,
    Recv,
) where

-- GHC packages
import Control.Concurrent (threadWaitReadSTM)
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.IntSet as Set
import GHC.Event (TimeoutKey, TimerManager, getSystemTimerManager, registerTimeout, updateTimeout)
import System.Posix.Types (Fd (..))

-- libs
import UnliftIO.Exception (SomeException (..), handle, throwIO)

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
    -> IO ([IO ()], [IO ()], ToCacher -> IO ())
    -- ^ (worker actions, cacher actions, input to cacher)
mkPipeline env cachersN _workersN workerStats = do
    {- limit waiting area on server to constant size -}
    let queueBound = 64
    qr <- newTBQueueIO queueBound
    let toCacher = atomically . writeTBQueue qr
        fromReceiver = atomically $ readTBQueue qr
    qw <- newTBQueueIO queueBound
    let toWorker = atomically . writeTBQueue qw
        fromCacher = atomically $ readTBQueue qw
    let cachers = replicate cachersN $ cacherLogic env fromReceiver toWorker
    let workers = [workerLogic env wstat fromCacher | wstat <- workerStats]
    return (cachers, workers, toCacher)

----------------------------------------------------------------

cacherLogic :: Env -> IO FromReceiver -> (ToWorker -> IO ()) -> IO ()
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
                    duration <- diffUsec <$> currentTimeUsec_ env <*> pure inputRecvTime
                    updateHistogram_ env duration (stats_ env)
                    mapM_ (incStats $ stats_ env) [CacheHit, QueriesAll]
                    let bs = DNS.encode replyMsg
                    record env inp replyMsg bs
                    inputToSender $ Output bs inputRequestNum inputPeerInfo
                CResultDenied _replyErr -> do
                    duration <- diffUsec <$> currentTimeUsec_ env <*> pure inputRecvTime
                    updateHistogram_ env duration (stats_ env)
                    logicDenied env inp

----------------------------------------------------------------

workerLogic :: Env -> WorkerStatOP -> IO FromCacher -> IO ()
workerLogic env WorkerStatOP{..} fromCacher = handledLoop env "worker" $ do
    setWorkerStat WWaitDequeue
    inp@Input{..} <- fromCacher
    case question inputQuery of
        q : _ -> setWorkerStat (WRun q)
        [] -> pure ()
    ex <- getResponseIterative env inputQuery
    duration <- diffUsec <$> currentTimeUsec_ env <*> pure inputRecvTime
    updateHistogram_ env duration (stats_ env)
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

{- FOURMOLU_DISABLE -}
record
    :: Env
    -> Input DNSMessage
    -> DNSMessage
    -> ByteString
    -> IO ()
record env Input{..} reply rspWire = do
    let peersa = peerSockAddr inputPeerInfo
    logDNSTAP_ env $ runEpochTimeUsec inputRecvTime $
        \s us -> DNSTAP.composeMessage inputProto inputMysa peersa s (fromIntegral us * 1000) rspWire
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
    when authAnswer   $ incStats st FlagAA
    when authenData   $ incStats st FlagAD
    when chkDisable   $ incStats st FlagCD
    when isResponse   $ incStats st FlagQR
    when recAvailable $ incStats st FlagRA
    when recDesired   $ incStats st FlagRD
    when trunCation   $ incStats st FlagTC
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

type Recv = IO (ByteString, PeerInfo)
type Send = ByteString -> PeerInfo -> IO ()

type MkInput = ByteString -> PeerInfo -> Int -> EpochTimeUsec -> Input ByteString

mkInput :: SockAddr -> (ToSender -> IO ()) -> SocketProtocol -> MkInput
mkInput mysa toSender proto bs peerInfo i = Input bs i mysa peerInfo proto toSender

receiverVC
    :: String
    -> Env
    -> VcSession
    -> Recv
    -> (ToCacher -> IO ())
    -> MkInput
    -> IO RxState
receiverVC name env vcs@VcSession{..} recv toCacher mkInput_ =
    loop 1 `E.catch` onError
  where
    onError se@(SomeException e) = warnOnError env name se >> throwIO e
    loop i = cases =<< waitVcInput vcs
      where
        cases RxOpen = do
            (bs, peerInfo) <- recv
            ts <- currentTimeUsec_ env
            casesSize (BS.length bs) bs peerInfo ts
        cases st = pure st
        casesSize sz bs peerInfo ts
            | sz == 0 = do
                resetVcTimeout vcRxState_
                caseEof
            | sz > vcSlowlorisSize_ = do
                resetVcTimeout vcRxState_
                step bs peerInfo ts
                loop (i + 1)
            | otherwise = do
                step bs peerInfo ts
                loop (i + 1)

        caseEof = atomically (setRxState vcRxState_ RxClosed) >> return RxClosed
        step bs peerInfo ts = do
            atomically $ addVcPending vcPendings_ i
            toCacher $ mkInput_ bs peerInfo i ts

receiverLogic
    :: Env -> SockAddr -> Recv -> (ToCacher -> IO ()) -> (ToSender -> IO ()) -> SocketProtocol -> IO ()
receiverLogic env mysa recv toCacher toSender proto =
    handledLoop env "receiverUDP" $ void $ receiverLogic' env mysa recv toCacher toSender proto

receiverLogic'
    :: Env -> SockAddr -> Recv -> (ToCacher -> IO ()) -> (ToSender -> IO ()) -> SocketProtocol -> IO Bool
receiverLogic' env mysa recv toCacher toSender proto = do
    (bs, peerInfo) <- recv
    ts <- currentTimeUsec_ env
    if bs == ""
        then return False
        else do
            toCacher $ Input bs 0 mysa peerInfo proto toSender ts
            return True

senderVC
    :: String
    -> Env
    -> VcSession
    -> Send
    -> IO FromX
    -> IO RxState
senderVC name env vcs@VcSession{..} send fromX = loop `E.catch` onError
  where
    -- logging async exception intentionally, for not expected `cancel`
    onError se@(SomeException e) = warnOnError env name se >> throwIO e
    loop = do
        x <- waitVcOutput vcs
        if x == RxOpen
            then do
                step
                loop
            else return x
    step = E.bracket fromX finalize $ \(Output bs _ peerInfo) -> do
        resetVcTimeout vcRxState_
        send bs peerInfo
    finalize (Output _ i _) = atomically (delVcPending vcPendings_ i)

senderLogic :: Env -> Send -> IO FromX -> IO ()
senderLogic env send fromX =
    handledLoop env "senderUDP" $ senderLogic' send fromX

senderLogic' :: Send -> IO FromX -> IO ()
senderLogic' send fromX = do
    Output bs _ peerInfo <- fromX
    send bs peerInfo

----------------------------------------------------------------

data RxState = RxOpen | RxClosed | RxTimeout deriving (Eq, Show)

{- FOURMOLU_DISABLE -}
data VcRxState
    = VcRxState
    { vrManager_  :: TimerManager
    , vrKey_      :: TimeoutKey
    , vrState_    :: TVar RxState
    , vrMicrosec_ :: Int
    }
{- FOURMOLU_ENABLE -}

type VcWaitRead = STM ()
type VcPendings = TVar Set.IntSet
type VcRespAvail = STM Bool
type VcAllowInput = STM Bool

{- FOURMOLU_DISABLE -}
data VcSession =
    VcSession
    { vcRxState_        :: VcRxState
    , vcPendings_       :: VcPendings
    , vcRespAvail_      :: VcRespAvail
    , vcAllowInput_     :: VcAllowInput
    , vcWaitRead_       :: IO VcWaitRead
    , vcSlowlorisSize_  :: Int
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
initVcRxState :: Int -> IO VcRxState
initVcRxState micro = do
    st  <- newTVarIO RxOpen
    mgr <- getSystemTimerManager
    key <- registerTimeout mgr micro (atomically $ writeTVar st RxTimeout)
    pure $
        VcRxState
            { vrManager_ = mgr
            , vrKey_ = key
            , vrState_ = st
            , vrMicrosec_ = micro
            }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
initVcSession :: IO VcWaitRead -> Int -> Int -> IO (VcSession, (ToSender -> IO ()), IO FromX)
initVcSession getWaitIn micro slsize = do
    vcRxState   <- initVcRxState micro
    vcPendings  <- newTVarIO Set.empty
    let queueBound = 8 {- limit waiting area per session to constant size -}
    senderQ     <- newTBQueueIO queueBound
    let toSender = atomically . writeTBQueue senderQ
        fromX = atomically $ readTBQueue senderQ
        inputThreshold = succ queueBound `quot` 2
        {- allow room for cacher loops and worker loops to write -}
        allowInput = (<= inputThreshold) <$> lengthTBQueue senderQ
        result =
            VcSession
            { vcRxState_        = vcRxState
            , vcPendings_       = vcPendings
            , vcRespAvail_      = not <$> isEmptyTBQueue senderQ
            , vcAllowInput_     = allowInput
            , vcWaitRead_       = getWaitIn
            , vcSlowlorisSize_  = slsize
            }
    pure (result, toSender, fromX)
{- FOURMOLU_ENABLE -}

getRxState :: VcRxState -> STM RxState
getRxState VcRxState{..} = readTVar vrState_

setRxState :: VcRxState -> RxState -> STM ()
setRxState VcRxState{..} = writeTVar vrState_

addVcPending :: VcPendings -> Int -> STM ()
addVcPending pendings i = modifyTVar' pendings (Set.insert i)

delVcPending :: VcPendings -> Int -> STM ()
delVcPending pendings i = modifyTVar' pendings (Set.delete i)

resetVcTimeout :: VcRxState -> IO ()
resetVcTimeout VcRxState{..} = updateTimeout vrManager_ vrKey_ vrMicrosec_

waitVcInput :: VcSession -> IO RxState
waitVcInput VcSession{..} = do
    waitIn <- vcWaitRead_
    atomically $ do
        st <- getRxState vcRxState_
        when (st == RxOpen) $ do
            retryUntil =<< vcAllowInput_
            waitIn
        return st

{- FOURMOLU_DISABLE -}
--   eof       timeout   pending     avail       sender-loop
--
--   eof       to        null        no-avail    break
--   not-eof   to        null        no-avail    break
--   eof       not-to    null        no-avail    break
--   not-eof   not-to    null        no-avail    wait
--   -         -         not-null    no-avail    wait
--   -         -         -           avail       loop
waitVcOutput :: VcSession -> IO RxState
waitVcOutput VcSession{..} = atomically $ do
    st <- getRxState vcRxState_
    avail  <- vcRespAvail_
    case st of
        RxOpen -> retryUntil avail >> return RxOpen
        _
            | avail -> return RxOpen -- fixme
            | otherwise -> do
                retryUntil . Set.null =<< readTVar vcPendings_
                return st
{- FOURMOLU_ENABLE -}

retryUntil :: Bool -> STM ()
retryUntil = guard

mkConnector :: IO (ToSender -> IO (), IO FromX, VcRespAvail, VcAllowInput)
mkConnector = do
    let queueBound = 8 {- limit waiting area per session to constant size -}
        inputThreshold = succ queueBound `quot` 2
    qs <- newTBQueueIO queueBound
    let toSender = atomically . writeTBQueue qs
        fromX = atomically $ readTBQueue qs
    return (toSender, fromX, not <$> isEmptyTBQueue qs, (<= inputThreshold) <$> lengthTBQueue qs)

----------------------------------------------------------------

waitReadSocketSTM' :: Socket -> IO (STM ())
waitReadSocketSTM' s = fst <$> waitReadSocketSTM s

waitReadSocketSTM :: Socket -> IO (STM (), IO ())
waitReadSocketSTM s = withFdSocket s $ threadWaitReadSTM . Fd

----------------------------------------------------------------

handledLoop :: Env -> String -> IO () -> IO ()
handledLoop env tag body = forever $ handle (warnOnError env tag) body

warnOnError :: Env -> String -> SomeException -> IO ()
warnOnError env tag (SomeException e) = logLn env Log.WARN (tag ++ ": exception: " ++ show e)

----------------------------------------------------------------

logLn :: Env -> Log.Level -> String -> IO ()
logLn env level = logLines_ env level Nothing . (: [])
