{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Main where

-- GHC
import Control.Concurrent (killThread, threadDelay)
import Control.Concurrent.Async (mapConcurrently_, race_)
import Control.Exception (bracket_, finally)
import Control.Monad
import Data.ByteString.Builder
import Data.Functor
import qualified Data.IORef as I
import Data.String (fromString)
import GHC.Stats
import System.Environment (getArgs)
import System.IO (IOMode (AppendMode), openFile, hClose)
import System.Posix (UserID, getRealUserID, setEffectiveGroupID, setEffectiveUserID)
import System.Posix (Handler (Catch), installHandler, sigHUP)
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
import Network.Socket hiding (close)
import Network.TLS (Credentials (..), credentialLoadX509)
import qualified Network.TLS.SessionTicket as ST

-- this package
import Config
import qualified DNSTAP as TAP
import qualified Monitor as Mon
import Prometheus
import SocketUtil
import Types
import qualified WebAPI as API

----------------------------------------------------------------

help :: IO ()
help = putStrLn "bowline [<confFile>] [<conf-key>=<conf-value> ...]"

----------------------------------------------------------------

run :: UserID -> IO Config -> IO ()
run ruid readConfig = do
    -- TimeCache uses Control.AutoUpdate which
    -- does not provide a way to kill the internal thread.
    tcache <- newTimeCache
    conf <- readConfig
    go tcache Nothing conf
  where
    go tcache mcache conf = do
        mng <- newControl readConfig
        gcache <- maybe (getCache tcache conf) return mcache
        void $ installHandler sigHUP (Catch $ reloadCmd mng KeepCache () ()) Nothing -- reloading with cache on SIGHUP
        runConfig tcache gcache mng ruid conf
        ctl <- getCommandAndClear mng
        case ctl of
            Quit -> putStrLn "\nQuiting..." -- fixme
            Reload rconf -> do
                putStrLn "\nReloading..." -- fixme
                stopCache $ gcacheRRCacheOps gcache
                go tcache Nothing rconf
            KeepCache rconf -> do
                putStrLn "\nReloading with the current cache..." -- fixme
                go tcache (Just gcache) rconf

runConfig :: TimeCache -> GlobalCache -> Control -> UserID -> Config -> IO ()
runConfig tcache gcache@GlobalCache{..} mng0 ruid conf@Config{..} = do
    -- Setup
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
    (runLogger, putLines, killLogger, reopenLog0) <- getLogger ruid conf tcache
    --
    let rootpriv = do
            (runWriter, putDNSTAP) <- TAP.new conf
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
                        , maxNegativeTTL_ = cropMaxNegativeTTL cnf_cache_max_negative_ttl
                        , failureRcodeTTL_ = cropFailureRcodeTTL cnf_cache_failure_rcode_ttl
                        , updateHistogram_ = updateHistogram
                        , timeout_ = tmout
                        }
            --  filled env available
            creds <- getCreds conf
            sm <- ST.newSessionTicketManager ST.defaultConfig{ST.ticketLifetime = cnf_tls_session_ticket_lifetime}
            addrs <- mapM (bindServers cnf_dns_addrs) $ trans creds sm
            (mas, monInfo) <- Mon.bindMonitor conf env
            masock <- API.bindAPI conf
            return (runWriter, env, addrs, mas, monInfo, masock)
    -- recover root-privilege to bind network-port and to access private-key on reloading
    (runWriter, env, addrs, mas, monInfo, masock) <- withRoot ruid conf rootpriv
    -- actions list for threads
    workerStats <- Server.getWorkerStats cnf_workers
    (cachers, workers, toCacher) <- Server.mkPipeline env cnf_cachers cnf_workers workerStats
    servers <- sequence [(n, sks,) <$> mkserv env toCacher sks | (n, mkserv, sks) <- addrs, not (null sks)]
    mng <- getControl env workerStats mng0{reopenLog = reopenLog0}
    let srvInfo1 name sas = unwords $ (name ++ ":") : map show sas
        monitors srvInfo = Mon.monitors conf env mng gcache srvInfo mas monInfo
    monitor <- monitors <$> mapM (\(n, _mk, sks) -> srvInfo1 n <$> mapM getSocketName sks) addrs
    -- Run
    gcacheSetLogLn putLines
    tidW <- runWriter
    runLogger
    tidA <- mapM (TStat.forkIO "webapi-srv" . API.run mng) masock
    let withNum name xs = zipWith (\i x -> (name ++ printf "%4d" i, x)) [1 :: Int ..] xs
    let concServer =
            conc
                [ TStat.concurrentlyList_ (withNum "cacher" cachers)
                , TStat.concurrentlyList_ (withNum "worker" workers)
                , TStat.concurrentlyList_ [(n, as) | (n, _sks, ass) <- servers, as <- ass]
                ]
    {- Advisedly separating 'dumper' thread from Async thread-tree
       - Keep the 'dumper' thread alive until the end for debugging purposes
       - Not to be affected by issued `cancel` to thread-tree
       The 'dumper' thread separated by forkIO automatically terminates
       when the 'main' thread ends, so there's no need for cleanup.          -}
    sequence_ [TStat.forkIO "dumper" (TStat.dumper $ putLines Log.SYSTEM Nothing) | cnf_threads_dumper]
    race_ concServer (conc monitor)
        -- Teardown
        `finally` do
            mapM_ maybeKill [tidA, tidW]
            killLogger
    threadDelay 500000 -- avoiding address already in use
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
    ruid <- getRealUserID
    case args of
        [] -> run ruid (return defaultConfig)
        a : _
            | a `elem` ["-h", "-help", "--help"] -> help
        confFile : aargs -> run ruid (parseConfig confFile aargs)

----------------------------------------------------------------

bindServers
    :: [HostName]
    -> (Bool, n, a, SocketType, PortNumber)
    -> IO (n, a, [Socket])
bindServers _     (False, n, a, _       , _   ) =    return (n, a, [])
bindServers hosts (True , n, a, socktype, port) = do
    as <- ainfosSkipError putStrLn socktype port hosts
    (n, a,) <$> mapM openBind as
  where
    openBind ai = do
        s <- openSocket ai
        setSocketOption s ReuseAddr 1
        when (addrFamily ai == AF_INET6) $ setSocketOption s IPv6Only 1
        withFdSocket s $ setCloseOnExecIfNeeded
        bind s $ addrAddress ai
        when (addrSocketType ai == Stream) $ listen s 1024
        return s

getServers
    :: Env
    -> [HostName]
    -> (Server.ToCacher -> IO ())
    -> (Bool, String, ServerActions, SocketType, PortNumber)
    -> IO [(String, [Socket], IO ())]
getServers _ _ _ (False, _, _, _, _) = return []
getServers env hosts toCacher (True, name, mkServer, socktype, port) = do
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

----------------------------------------------------------------

getCache :: TimeCache -> Config -> IO GlobalCache
getCache tc Config{..} = do
    ref <- I.newIORef $ \_ _ _ -> return ()
    let memoLogLn msg = do
            putLines <- I.readIORef ref
            putLines Log.WARN Nothing [msg]
        cacheConf = RRCacheConf cnf_cache_size 1800 memoLogLn $ Server.getTime tc
    cacheOps <- newRRCacheOps cacheConf
    let setLog = I.writeIORef ref
    return $ GlobalCache cacheOps (getCacheControl cacheOps) setLog

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
getCacheControl :: RRCacheOps -> CacheControl
getCacheControl RRCacheOps{..} =
    emptyCacheControl
    { ccRemove = rmName, ccRemoveType = rmType, ccRemoveBogus = rmBogus, ccRemoveNegative = rmNeg, ccClear = clearCache }
  where
    rmName name     = mapM_ (rmType name) types
    rmType name ty  = removeCache (DNS.Question name ty DNS.IN)
    types = [A, AAAA, NS, SOA, CNAME, DNAME, MX, PTR, SRV, TYPE 35, SVCB, HTTPS]
    rmBogus   = filterCache (\_ _ hit _ -> Cache.hitCases1 (\_ -> True) notBogus hit)
    notBogus  = Cache.positiveCases (\_ -> True) (\_ -> False) (\_ _ -> True)
    rmNeg     = filterCache (\_ _ hit _ -> Cache.hitCases1 (\_ -> False) (\_ -> True) hit)
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

{- FOURMOLU_DISABLE -}
getLogger :: UserID -> Config -> TimeCache -> IO (IO (), Log.PutLines IO, IO (), IO ())
getLogger ruid conf@Config{..} TimeCache{..}
    | cnf_log = do
        let getpts
                | cnf_log_timestamp  = getTimeStr <&> (. (' ' :))
                | otherwise          = pure id
            result hreop a _ p k r = return (void $ TStat.forkIO "logger" a, p, k, hreop r)
            lk open close fr = Log.with getpts open close cnf_log_level (result fr)
            handle   = lk (pure $ Log.stdHandle cnf_log_output)         (\_ -> pure ()) (\_ -> pure ())
            file fn  = lk (withRoot ruid conf $ openFile fn AppendMode)  hClose         (\r -> r)
        maybe handle file cnf_log_file
    | otherwise = do
        let p _ _ ~_ = return ()
            n = return ()
        return (return (), p, n, n)
{- FOURMOLU_ENABLE -}

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
    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
        mng =
            mng0
                { getStats = getStats' env ucacheQSize
                , getWStats = getWStats' wstats
                }
    return mng

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

recoverRoot :: IO ()
recoverRoot= do
    setEffectiveUserID 0
    setEffectiveGroupID 0

-- | Setting user and group.
setGroupUser :: Config -> IO ()
setGroupUser Config{..} = do
    setEffectiveGroupID cnf_group
    setEffectiveUserID cnf_user

withRoot :: UserID -> Config -> IO a -> IO a
withRoot ruid conf act
    | ruid == 0 = bracket_ recoverRoot (setGroupUser conf) act
    | otherwise = act
