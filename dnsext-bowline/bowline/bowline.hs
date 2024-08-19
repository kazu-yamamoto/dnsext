{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Main where

-- GHC
import Control.Concurrent (ThreadId, forkIO, killThread, threadDelay)
import Control.Concurrent.Async (mapConcurrently_, race_, wait)
import Control.Concurrent.STM
import Control.Monad (guard, when)
import Data.ByteString.Builder
import Data.Functor
import qualified Data.IORef as I
import Data.String (fromString)
import GHC.Stats
import System.Environment (getArgs)
import System.Posix (
    getGroupEntryForName,
    getRealUserID,
    getUserEntryForName,
    groupID,
    setGroupID,
    setUserID,
    userID,
 )
import System.Timeout (timeout)
import Text.Printf (printf)

-- dnsext-* deps
import DNS.Iterative.Server as Server
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import qualified DNS.SEC as DNS
import DNS.SVCB (TYPE (..))
import qualified DNS.SVCB as DNS
import qualified DNS.ThreadStats as TStat
import qualified DNS.Types as DNS
import DNS.Types.Internal (TYPE (..))
import Network.Socket
import Network.TLS (Credentials (..), credentialLoadX509)
import qualified Network.TLS.SessionTicket as ST
import UnliftIO.Exception (finally)

-- this package
import Config
import qualified DNSTAP as TAP
import qualified Monitor as Mon
import Prometheus
import SocketUtil
import Types
import qualified WebAPI as API

----------------------------------------------------------------

data GlobalCache = GlobalCache
    { gcacheRRCacheOps :: RRCacheOps
    , gcacheSetLogLn :: Log.PutLines IO -> IO ()
    }

----------------------------------------------------------------

help :: IO ()
help = putStrLn "bowline [<confFile>] [<conf-key>=<conf-value> ...]"

----------------------------------------------------------------

run :: IO Config -> IO ()
run readConfig = do
    -- TimeCache uses Control.AutoUpdate which
    -- does not provide a way to kill the internal thread.
    tcache <- newTimeCache
    newControl >>= go tcache Nothing
  where
    go tcache mcache mng = do
        cache <- readConfig >>= runConfig tcache mcache mng
        ctl <- getCommandAndClear mng
        case ctl of
            Quit -> putStrLn "\nQuiting..." -- fixme
            Reload -> do
                putStrLn "\nReloading..." -- fixme
                stopCache $ gcacheRRCacheOps cache
                go tcache Nothing mng
            KeepCache -> do
                putStrLn "\nReloading with the current cache..." -- fixme
                go tcache (Just cache) mng

runConfig :: TimeCache -> Maybe GlobalCache -> Control -> Config -> IO GlobalCache
runConfig tcache mcache mng0 conf@Config{..} = do
    -- Setup
    gcache@GlobalCache{..} <- case mcache of
        Nothing -> getCache tcache conf
        Just c -> return c
    (runWriter, putDNSTAP) <- TAP.new conf
    (runLogger, putLines, killLogger) <- getLogger conf
    gcacheSetLogLn putLines
    let tmout = timeout cnf_resolve_timeout
        check_for_v6_ns
            | cnf_disable_v6_ns = pure True
            | otherwise = do
                let disabled _ = putStrLn "cnf_disable_v6_ns is False, but disabling, because IPv6 is not supported." $> True
                foldAddrInfo disabled (\_ -> pure False) Datagram (Just "::") 53
        readTrustAnchors' ps = do
            when (not $ null ps) $ putStrLn $ "loading trust-anchor-file: " ++ (unwords ps)
            readTrustAnchors ps
        readRootHint' path = do
            putStrLn $ "loading root-hints: " ++ path
            readRootHint path
    disable_v6_ns <- check_for_v6_ns
    trustAnchors <- readTrustAnchors' cnf_trust_anchor_file
    rootHint <- mapM readRootHint' cnf_root_hints
    let setOps = setRootHint rootHint . setRootAnchor trustAnchors . setRRCacheOps gcacheRRCacheOps . setTimeCache tcache
        localZones = getLocalZones cnf_local_zones
    stubZones <- getStubZones cnf_stub_zones trustAnchors
    updateHistogram <- getUpdateHistogram $ putStrLn "response_time_seconds_sum is not supported for Int shorter than 64bit."
    env <-
        newEnv <&> \env0 ->
            (setOps env0)
                { shortLog_ = cnf_short_log
                , logLines_ = putLines
                , logDNSTAP_ = putDNSTAP
                , disableV6NS_ = disable_v6_ns
                , localZones_ = localZones
                , stubZones_ = stubZones
                , maxNegativeTTL_ = fromIntegral cnf_cache_max_negative_ttl
                , updateHistogram_ = updateHistogram
                , timeout_ = tmout
                }
    creds <- getCreds conf
    sm <- ST.newSessionTicketManager ST.defaultConfig{ST.ticketLifetime = cnf_tls_session_ticket_lifetime}
    workerStats <- Server.getWorkerStats cnf_workers
    (cachers, workers, toCacher) <- Server.mkPipeline env cnf_cachers cnf_workers workerStats
    servers <- mapM (getServers env cnf_dns_addrs toCacher) $ trans creds sm
    mng <- getControl env workerStats mng0
    let srvinfo name sockets = do
            sas <- mapM getSocketName sockets
            pure $ unwords $ (name ++ ":") : map show sas
    monitor <- Mon.monitor conf env mng =<< sequence [srvinfo n sks | svs <- servers, (n, sks, _as) <- svs]
    --
    void $ setGroupUser cnf_user cnf_group
    -- Run
    tidW <- runWriter
    _tidL <- runLogger
    tidA <- API.new conf mng
    let withNum name xs = zipWith (\i x -> (name ++ printf "%4d" i, x)) [1 :: Int ..] xs
    let concServer =
            conc
                ( [TStat.withAsync "dumper" (TStat.dumper $ putLines Log.SYSTEM Nothing) wait | cnf_threads_dumper]
                    ++ [ TStat.concurrentlyList_ (withNum "cacher" cachers)
                       , TStat.concurrentlyList_ (withNum "worker" workers)
                       , TStat.concurrentlyList_ [(n, as) | svs <- servers, (n, _sks, as) <- svs]
                       ]
                )
    race_ concServer (conc monitor)
        -- Teardown
        `finally` do
            mapM_ maybeKill [tidA, tidW]
            killLogger
    threadDelay 500000 -- avoiding address already in use
    return gcache
  where
    maybeKill = maybe (return ()) killThread
    trans creds sm =
        [ (cnf_udp, "udp-srv", udpServers udpconf, Datagram, cnf_udp_port)
        , (cnf_tcp, "tcp-srv", tcpServers vcconf, Stream, cnf_tcp_port)
        , (cnf_h2c, "h2c-srv", http2cServers vcconf, Stream, cnf_h2c_port)
        , (cnf_h2, "h2-srv", http2Servers vcconf, Stream, cnf_h2_port)
        , (cnf_h3, "h3-srv", http3Servers vcconf, Datagram, cnf_h3_port)
        , (cnf_tls, "tls-srv", tlsServers vcconf, Stream, cnf_tls_port)
        , (cnf_quic, "quic-srv", quicServers vcconf, Datagram, cnf_quic_port)
        ]
      where
        vcconf =
            VcServerConfig
                { vc_query_max_size = cnf_vc_query_max_size
                , vc_idle_timeout = cnf_vc_idle_timeout
                , vc_slowloris_size = cnf_vc_slowloris_size
                , vc_credentials = creds
                , vc_session_manager = sm
                , vc_early_data_size = cnf_early_data_size
                , vc_interface_automatic = cnf_interface_automatic
                }
    conc = mapConcurrently_ id
    udpconf =
        UdpServerConfig
            { udp_interface_automatic = cnf_interface_automatic
            }

main :: IO ()
main = do
    DNS.runInitIO $ do
        DNS.addResourceDataForDNSSEC
        DNS.addResourceDataForSVCB
    args <- getArgs
    case args of
        [] -> run (return defaultConfig)
        a : _
            | a `elem` ["-h", "-help", "--help"] -> help
        confFile : aargs -> run (parseConfig confFile aargs)

----------------------------------------------------------------

getServers
    :: Env
    -> [HostName]
    -> Server.ToCacher
    -> (Bool, String, ServerActions, SocketType, Int)
    -> IO [(String, [Socket], IO ())]
getServers _ _ _ (False, _, _, _, _) = return []
getServers env hosts toCacher (True, name, mkServer, socktype, port') = do
    as <- ainfosSkipError putStrLn socktype port hosts
    sockets <- mapM openBind as
    map (name,sockets,) <$> mkServer env toCacher sockets
  where
    openBind ai = do
        s <- openSocket ai
        setSocketOption s ReuseAddr 1
        when (addrFamily ai == AF_INET6) $ setSocketOption s IPv6Only 1
        withFdSocket s $ setCloseOnExecIfNeeded
        bind s $ addrAddress ai
        when (addrSocketType ai == Stream) $ listen s 1024
        return s
    port = fromIntegral port'

----------------------------------------------------------------

getCache :: TimeCache -> Config -> IO GlobalCache
getCache tc@TimeCache{..} Config{..} = do
    ref <- I.newIORef Nothing
    let memoLogLn msg = do
            mx <- I.readIORef ref
            case mx of
                Nothing -> return ()
                Just putLines -> do
                    tstr <- getTimeStr
                    putLines Log.WARN Nothing [tstr $ ": " ++ msg]
        cacheConf = RRCacheConf cnf_cache_size 1800 memoLogLn $ Server.getTime tc
    cacheOps <- newRRCacheOps cacheConf
    let setLog = I.writeIORef ref . Just
    return $ GlobalCache cacheOps setLog

----------------------------------------------------------------

getLogger :: Config -> IO (IO (Maybe ThreadId), Log.PutLines IO, IO ())
getLogger Config{..}
    | cnf_log = do
        (r, p, f) <- Log.new cnf_log_output cnf_log_level
        return (Just <$> forkIO r, p, f)
    | otherwise = do
        let p _ _ ~_ = return ()
            f = return ()
        return (return Nothing, p, f)

----------------------------------------------------------------

getCreds :: Config -> IO Credentials
getCreds Config{..}
    | cnf_tls || cnf_quic || cnf_h2 || cnf_h3 = do
        Right cred@(!_cc, !_priv) <- credentialLoadX509 cnf_cert_file cnf_key_file
        return $ Credentials [cred]
    | otherwise = return $ Credentials []

----------------------------------------------------------------

getControl :: Env -> [WorkerStatOP] -> Control -> IO Control
getControl env wstats mng0 = do
    qRef <- newTVarIO False
    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
        mng =
            mng0
                { getStats = getStats' env ucacheQSize
                , getWStats = getWStats' wstats
                , cacheControl = getCacheControl env
                , quitServer = atomically $ writeTVar qRef True
                , waitQuit = readTVar qRef >>= guard
                }
    return mng

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
getCacheControl :: Env -> CacheControl
getCacheControl Env{..} =
    emptyCacheControl
    { ccRemove = rmName, ccRemoveType = rmType, ccRemoveBogus = rmBogus, ccRemoveNegative = rmNeg, ccClear = clearCache_ }
  where
    rmName name     = mapM_ (rmType name) types
    rmType name ty  = removeCache_ (DNS.Question name ty DNS.IN)
    types = [A, AAAA, NS, SOA, CNAME, DNAME, MX, PTR, SRV, TYPE 35, SVCB, HTTPS]
    rmBogus = filterCache_ (\_ _ hit _ -> Cache.hitCases1 (\_ -> True) notBogus hit)
    notBogus = Cache.positiveCases (\_ -> True) (\_ -> False) (\_ _ -> True)
    rmNeg = filterCache_ (\_ _ hit _ -> Cache.hitCases1 (\_ -> False) (\_ -> True) hit)
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

getStats' :: Env -> IO (Int, Int) -> IO Builder
getStats' env _ucacheQSize = do
    enabled <- getRTSStatsEnabled
    gc <-
        if enabled
            then fromRTSStats <$> getRTSStats
            else return mempty
    st <- Server.getStats env "bowline_"
    return (gc <> st)

----------------------------------------------------------------

getWStats' :: [WorkerStatOP] -> IO Builder
getWStats' wstats = fromString . unlines <$> Server.pprWorkerStats 0 wstats

----------------------------------------------------------------

-- | Checking if this process has the root privilege.
amIrootUser :: IO Bool
amIrootUser = (== 0) <$> getRealUserID

-- | Setting user and group.
setGroupUser
    :: String
    -- ^ User
    -> String
    -- ^ Group
    -> IO Bool
setGroupUser user group = do
    root <- amIrootUser
    if root
        then do
            getGroupEntryForName group >>= setGroupID . groupID
            getUserEntryForName user >>= setUserID . userID
            return True
        else
            return False
