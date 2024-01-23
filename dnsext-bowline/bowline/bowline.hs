{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent (ThreadId, forkIO, killThread, threadDelay)
import Control.Concurrent.Async (concurrently_, race_)
import Control.Concurrent.STM
import Control.Monad (guard)
import DNS.Iterative.Server as Server
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import qualified DNS.SEC as DNS
import qualified DNS.SVCB as DNS
import qualified DNS.Types as DNS
import Data.ByteString.Builder
import qualified Data.IORef as I
import Data.String (fromString)
import GHC.Stats
import Network.TLS (Credentials (..), credentialLoadX509)
import System.Environment (getArgs)
import System.Timeout (timeout)
import UnliftIO.Exception (finally)

import Config
import qualified DNSTAP as TAP
import qualified Monitor as Mon
import Prometheus
import Types
import qualified WebAPI as API

----------------------------------------------------------------

data GlobalCache = GlobalCache
    { gcacheRRCacheOps :: Cache.RRCacheOps
    , gcacheSetLogLn :: Log.PutLines -> IO ()
    }

----------------------------------------------------------------

help :: IO ()
help = putStrLn "bowline [<confFile>]"

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
    (runLogger, putLines, flush) <- getLogger conf
    gcacheSetLogLn putLines
    let tmout = timeout cnf_resolve_timeout
    env <- newEnv putLines putDNSTAP cnf_disable_v6_ns gcacheRRCacheOps tcache tmout
    creds <- getCreds conf
    workerStats <- Server.getWorkerStats cnf_workers
    (pipes, toCacher) <- Server.mkPipeline env cnf_cachers cnf_workers workerStats
    servers <- mapM (getServers env cnf_dns_addrs toCacher) $ trans creds
    mng <- getControl env workerStats mng0
    monitor <- Mon.monitor conf env mng
    -- Run
    tidW <- runWriter
    tidL <- runLogger
    tidA <- API.new conf mng
    race_ (conc $ pipes ++ concat servers) (conc monitor)
        -- Teardown
        `finally` do
            mapM_ maybeKill [tidA, tidL, tidW]
            flush
    threadDelay 500000 -- avoiding address already in use
    return gcache
  where
    maybeKill = maybe (return ()) killThread
    trans creds =
        [ (cnf_udp, udpServer udpconf, cnf_udp_port)
        , (cnf_tcp, tcpServer vcconf, cnf_tcp_port)
        , (cnf_h2c, http2cServer vcconf, cnf_h2c_port)
        , (cnf_h2, http2Server creds vcconf, cnf_h2_port)
        , (cnf_h3, http3Server creds vcconf, cnf_h3_port)
        , (cnf_tls, tlsServer creds vcconf, cnf_tls_port)
        , (cnf_quic, quicServer creds vcconf, cnf_quic_port)
        ]
    conc = foldr concurrently_ $ return ()
    udpconf =
        UdpServerConfig{}
    vcconf =
        VcServerConfig
            { vc_query_max_size = cnf_vc_query_max_size
            , vc_idle_timeout = cnf_vc_idle_timeout
            , vc_slowloris_size = cnf_vc_slowloris_size
            }

main :: IO ()
main = do
    DNS.runInitIO $ do
        DNS.addResourceDataForDNSSEC
        DNS.addResourceDataForSVCB
    args <- getArgs
    case args of
        [] -> run (return defaultConfig)
        [confFile] -> run (parseConfig confFile)
        _ -> help

----------------------------------------------------------------

getServers
    :: Env
    -> [HostName]
    -> Server.ToCacher
    -> (Bool, Server, Int)
    -> IO [IO ()]
getServers _ _ _ (False, _, _) = return []
getServers env hosts toCacher (True, server, port') =
    concat <$> mapM (server env toCacher port) hosts
  where
    port = fromIntegral port'

----------------------------------------------------------------

getCache :: TimeCache -> Config -> IO GlobalCache
getCache TimeCache{..} Config{..} = do
    ref <- I.newIORef Nothing
    let memoLogLn msg = do
            mx <- I.readIORef ref
            case mx of
                Nothing -> return ()
                Just putLines -> do
                    tstr <- getTimeStr
                    putLines Log.WARN Nothing [tstr $ ": " ++ msg]
        cacheConf = Cache.RRCacheConf cnf_cache_size 1800 memoLogLn getTime
    cacheOps <- Cache.newRRCacheOps cacheConf
    let setLog = I.writeIORef ref . Just
    return $ GlobalCache cacheOps setLog

----------------------------------------------------------------

getLogger :: Config -> IO (IO (Maybe ThreadId), Log.PutLines, IO ())
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
                , quitServer = atomically $ writeTVar qRef True
                , waitQuit = readTVar qRef >>= guard
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
