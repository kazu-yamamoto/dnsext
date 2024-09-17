{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.Pipeline (
    mkPipeline,
    mkConnector,
    mkInput,
    noPendingOp,
    getWorkerStats,
    VcFinished (..),
    VcPendings,
    VcTimer (..),
    VcSession (..),
    withVcTimer,
    initVcSession,
    waitVcInput,
    waitVcOutput,
    enableVcEof,
    enableVcTimeout,
    addVcPending,
    delVcPending,
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
import Control.Concurrent.STM
import Control.Exception (Exception (..), SomeException (..), AsyncException, bracket, handle, throwIO)
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import qualified Data.IntSet as Set
import GHC.Event (TimeoutKey, TimerManager, getSystemTimerManager, registerTimeout, updateTimeout, unregisterTimeout)

-- libs
import Control.Concurrent.Async (AsyncCancelled)

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
                    inputToSender $ Output bs inputPendingOp inputPeerInfo
                CResultDenied _replyErr -> do
                    duration <- diffUsec <$> currentTimeUsec_ env <*> pure inputRecvTime
                    updateHistogram_ env duration (stats_ env)
                    logicDenied env inp
                    vpDelete inputPendingOp

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
            inputToSender $ Output bs inputPendingOp inputPeerInfo
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
        Question{..} = case question inputQuery of
          [] -> error "record"
          q:_ -> q
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

type MkInput = ByteString -> PeerInfo -> VcPendingOp -> EpochTimeUsec -> Input ByteString

mkInput :: SockAddr -> (ToSender -> IO ()) -> SocketProtocol -> MkInput
mkInput mysa toSender proto bs peerInfo pendingOp = Input bs pendingOp mysa peerInfo proto toSender

receiverVC
    :: String
    -> Env
    -> VcSession
    -> VcTimer
    -> Recv
    -> (ToCacher -> IO ())
    -> MkInput
    -> IO VcFinished
receiverVC name env vcs@VcSession{..} timer recv toCacher mkInput_ =
    loop 1 `E.catch` onError
  where
    onError se@(SomeException e) = warnOnError env name se >> throwIO e
    loop i = cases =<< waitVcInput vcs
      where
        cases timeout
            | timeout = pure VfTimeout
            | otherwise = do
                (bs, peerInfo) <- recv
                ts <- currentTimeUsec_ env
                casesSize (BS.length bs) bs peerInfo ts
        casesSize sz bs peerInfo ts
            | sz == 0 = do
                resetVcTimer timer
                caseEof
            | sz > vcSlowlorisSize_ = do
                resetVcTimer timer
                step bs peerInfo ts
                loop (i + 1)
            | otherwise = do
                step bs peerInfo ts
                loop (i + 1)

        caseEof = atomically (enableVcEof vcEof_) >> return VfEof
        step bs peerInfo ts = do
            atomically $ addVcPending vcPendings_ i
            let delPending = atomically $ delVcPending vcPendings_ i
            toCacher $ mkInput_ bs peerInfo (VcPendingOp{vpReqNum = i, vpDelete = delPending}) ts

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
            toCacher $ Input bs noPendingOp mysa peerInfo proto toSender ts
            return True

noPendingOp :: VcPendingOp
noPendingOp = VcPendingOp{vpReqNum = 0, vpDelete = pure ()}

senderVC
    :: String
    -> Env
    -> VcSession
    -> VcTimer
    -> Send
    -> IO FromX
    -> IO VcFinished
senderVC name env vcs timer send fromX = loop `E.catch` onError
  where
    -- logging async exception intentionally, for not expected `cancel`
    onError se@(SomeException e) = warnOnError env name se >> throwIO e
    loop = do
        mx <- waitVcOutput vcs
        case mx of
            Just x -> return x
            Nothing -> step >> loop
    step = E.bracket fromX finalize $ \(Output bs _ peerInfo) -> do
        resetVcTimer timer
        send bs peerInfo
    finalize (Output _ VcPendingOp{..} _) = vpDelete

senderLogic :: Env -> Send -> IO FromX -> IO ()
senderLogic env send fromX =
    handledLoop env "senderUDP" $ senderLogic' send fromX

senderLogic' :: Send -> IO FromX -> IO ()
senderLogic' send fromX = do
    Output bs _ peerInfo <- fromX
    send bs peerInfo

----------------------------------------------------------------

type VcEof = TVar Bool
type VcWaitRead = STM ()
type VcPendings = TVar Set.IntSet
type VcRespAvail = STM Bool
type VcAllowInput = STM Bool

{- FOURMOLU_DISABLE -}
data VcTimer =
    VcTimer
    { vtManager_        :: TimerManager
    , vtKey_            :: TimeoutKey
    , vtMicrosec_       :: Int
    }
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data VcSession =
    VcSession
    { vcEof_            :: VcEof
    -- ^ EOF is received. This is an RX evet.
    , vcTimeout_        :: TVar Bool
    -- ^ TimerManager tells timed-out. This is another RX event
    --   but defined independently on EOF to make recording event simpler.
    , vcPendings_       :: VcPendings
    -- ^ A set of jobs. A job is that a request is received but
    --   a response is not sent. This design can take the pipeline
    --   as a blackbox since the sender increases it and the receiver
    --   decreases it.
    , vcRespAvail_      :: VcRespAvail
    -- ^ Jobs are available to the sender. This is necessary to
    --   tell whether or not the queue to the sender is empty or not
    --   WITHOUT IO.
    , vcAllowInput_     :: VcAllowInput
    , vcWaitRead_       :: IO VcWaitRead
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
initVcTimer :: Int -> IO () -> IO VcTimer
initVcTimer micro actionTO = do
    mgr <- getSystemTimerManager
    key <- registerTimeout mgr micro actionTO
    pure $ VcTimer mgr key micro
{- FOURMOLU_ENABLE -}

finalizeVcTimer :: VcTimer -> IO ()
finalizeVcTimer VcTimer{..} = unregisterTimeout vtManager_ vtKey_

withVcTimer
    :: Int -> IO ()
    -> (VcTimer -> IO a)
    -> IO a
withVcTimer micro actionTO = bracket (initVcTimer micro actionTO) finalizeVcTimer

{- FOURMOLU_DISABLE -}
initVcSession :: IO VcWaitRead -> Int -> IO (VcSession, (ToSender -> IO ()), IO FromX)
initVcSession getWaitIn slsize = do
    vcEof       <- newTVarIO False
    vcTimeout   <- newTVarIO False
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
            { vcEof_            = vcEof
            , vcTimeout_        = vcTimeout
            , vcPendings_       = vcPendings
            , vcRespAvail_      = not <$> isEmptyTBQueue senderQ
            , vcAllowInput_     = allowInput
            , vcWaitRead_       = getWaitIn
            , vcSlowlorisSize_  = slsize
            }
    pure (result, toSender, fromX)
{- FOURMOLU_ENABLE -}

enableVcEof :: VcEof -> STM ()
enableVcEof eof = writeTVar eof True

enableVcTimeout :: TVar Bool -> STM ()
enableVcTimeout timeout = writeTVar timeout True

addVcPending :: VcPendings -> Int -> STM ()
addVcPending pendings i = modifyTVar' pendings (Set.insert i)

delVcPending :: VcPendings -> Int -> STM ()
delVcPending pendings i = modifyTVar' pendings (Set.delete i)

resetVcTimer :: VcTimer -> IO ()
resetVcTimer VcTimer{..} = updateTimeout vtManager_ vtKey_ vtMicrosec_

waitVcInput :: VcSession -> IO Bool
waitVcInput VcSession{..} = do
    waitIn <- vcWaitRead_
    atomically $ do
        timeout <- readTVar vcTimeout_
        unless timeout $ do
            retryUntil =<< vcAllowInput_
            waitIn
        return timeout

{- FOURMOLU_DISABLE -}
--   eof       timeout   pending     avail       sender-loop
--
--   eof       to        null        no-avail    break
--   not-eof   to        null        no-avail    break
--   eof       not-to    null        no-avail    break
--   not-eof   not-to    null        no-avail    wait
--   -         -         not-null    no-avail    wait
--   -         -         -           avail       loop
--
-- If we consider to merge eof and timeout to rx state including
-- open|closed|timed-out, the table could be:
--
--   state     pending     avail       sender-loop
--
--   open      null        no-avail    wait
--   _         null        no-avail    break
--   -         not-null    no-avail    wait
--   -         -           avail       loop
waitVcOutput :: VcSession -> IO (Maybe VcFinished)
waitVcOutput VcSession{..} = atomically $ do
    mayEof <- toMaybe VfEof     <$> readTVar vcEof_
    mayTo  <- toMaybe VfTimeout <$> readTVar vcTimeout_
    avail  <- vcRespAvail_
    case mayEof <|> mayTo of
        -- Rx is open. Waiting for jobs for the sender without IO.
        -- When a job is available, Nothing is returned.
        Nothing -> retryUntil avail >> return Nothing
        -- Rx is closed.
        -- If jobs are available, just returns Nothing.
        -- Otherwise, the pipeline are processing jobs which
        -- are eventually passed to the sender if we "retry".
        -- After several retries AND available is false
        -- AND pending is null, the sender can finish.
        Just fc
            | avail -> return Nothing
            | otherwise -> do
                retryUntil . Set.null =<< readTVar vcPendings_
                return $ Just fc
  where
    toMaybe x True  = Just x
    toMaybe _ False = Nothing
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

{- FOURMOLU_DISABLE -}
handledLoop :: Env -> String -> IO () -> IO ()
handledLoop env tag body = forever $ handle (\e -> warnOnError env tag e >> takeEx e) body
  where
    takeEx :: SomeException -> IO ()
    takeEx e
        | Just ae <- fromException e :: Maybe AsyncCancelled  = throwIO ae
        | Just ae <- fromException e :: Maybe AsyncException  = throwIO ae
        | otherwise                                           = pure ()
{- FOURMOLU_ENABLE -}

warnOnError :: Env -> String -> SomeException -> IO ()
warnOnError env tag (SomeException e) = logLn env Log.WARN (tag ++ ": exception: " ++ show e)

----------------------------------------------------------------

logLn :: Env -> Log.Level -> String -> IO ()
logLn env level = logLines_ env level Nothing . (: [])
