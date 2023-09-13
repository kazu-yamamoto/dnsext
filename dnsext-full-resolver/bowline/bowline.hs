{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent (ThreadId, forkIO, getNumCapabilities, killThread, threadDelay)
import Control.Concurrent.STM
import Control.Monad (guard, mapAndUnzipM)
import DNS.Cache.Iterative (Env (..))
import qualified DNS.Cache.Iterative as Iterative
import DNS.Cache.Server
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.SEC as DNS
import qualified DNS.SVCB as DNS
import qualified DNS.Types as DNS
import qualified Data.IORef as I
import Data.List (intercalate)
import Network.TLS (Credentials (..), credentialLoadX509)
import System.Environment (getArgs)
import UnliftIO (concurrently_, race_)

import Config
import qualified DNSTAP as TAP
import Manage
import qualified Monitor as Mon
import qualified WebAPI as API

----------------------------------------------------------------

type GlobalCache =
    ( Iterative.TimeCache
    , Iterative.UpdateCache
    , Log.PutLines -> IO ()
    )

----------------------------------------------------------------

help :: IO ()
help = putStrLn "bowline [<confFile>]"

----------------------------------------------------------------

run :: IO Config -> IO ()
run readConfig = do
    -- Read config only to get cache size, sigh
    cache <- readConfig >>= getCache
    newManage >>= go (Just cache)
  where
    go mcache mng = do
        cache <- readConfig >>= runConfig mcache mng
        ctl <- getControlAndClear mng
        case ctl of
            Quit -> putStrLn "\nQuiting..." -- fixme
            Reload -> do
                putStrLn "\nReloading..." -- fixme
                go Nothing mng
            KeepCache -> do
                putStrLn "\nReloading with the current cache..." -- fixme
                go (Just cache) mng

runConfig :: Maybe GlobalCache -> Manage -> Config -> IO GlobalCache
runConfig mcache mng0 conf@Config{..} = do
    -- Setup
    cache@(tcache, updateCache, setLogger) <- case mcache of
        Nothing -> getCache conf -- fixme: reaper leak
        Just c -> return c
    (runWriter, putDNSTAP) <- TAP.new conf
    (runLogger, putLines, flush) <- getLogger conf
    setLogger putLines
    env <- Iterative.newEnv putLines putDNSTAP cnf_disable_v6_ns updateCache tcache
    creds <- getCreds conf
    (servers, statuses) <-
        mapAndUnzipM (getServers env cnf_dns_addrs) $ trans creds
    mng <- getManage env mng0 statuses
    monitor <- Mon.monitor conf env mng
    -- Run
    tidW <- runWriter
    tidL <- runLogger
    tidA <- API.new conf mng
    race_ (conc $ concat servers) (conc monitor)
    -- Teardown
    mapM_ (maybe (return ()) killThread) [tidA, tidL, tidW]
    flush
    threadDelay 500000 -- avoiding address already in use
    return cache
  where
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
        UdpServerConfig
            { udp_pipelines_per_socket = cnf_udp_pipelines_per_socket
            , udp_workers_per_pipeline = cnf_udp_workers_per_pipeline
            , udp_queue_size_per_pipeline = cnf_udp_queue_size_per_pipeline
            , udp_pipeline_share_queue = cnf_udp_pipeline_share_queue
            }
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
    -> (Bool, Server, Int)
    -> IO ([IO ()], [IO Status])
getServers _ _ (False, _, _) = return ([], [])
getServers env hosts (True, server, port') = do
    (xss, yss) <- mapAndUnzipM (server env port) hosts
    let xs = concat xss
        ys = concat yss
    return (xs, ys)
  where
    port = fromIntegral port'

----------------------------------------------------------------

getCache :: Config -> IO GlobalCache
getCache Config{..} = do
    ref <- I.newIORef Nothing
    tcache@(getSec, getTimeStr) <- TimeCache.new
    let cacheConf = Cache.MemoConf cnf_cache_size 1800 memoActions
          where
            memoLogLn msg = do
                mx <- I.readIORef ref
                case mx of
                    Nothing -> return ()
                    Just putLines -> do
                        tstr <- getTimeStr
                        putLines Log.WARN Nothing [tstr $ ": " ++ msg]
            memoActions = Cache.MemoActions memoLogLn getSec
    updateCache <- Iterative.getUpdateCache cacheConf
    return (tcache, updateCache, I.writeIORef ref . Just)

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

getManage :: Env -> Manage -> [[IO Status]] -> IO Manage
getManage env mng0 statuses = do
    qRef <- newTVarIO False
    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
        mng =
            mng0
                { getStatus = getStatus' env (concat statuses) ucacheQSize
                , quitServer = atomically $ writeTVar qRef True
                , waitQuit = readTVar qRef >>= guard
                }
    return mng

----------------------------------------------------------------

getStatus' :: Env -> [IO Status] -> IO (Int, Int) -> IO String
getStatus' env iss ucacheQSize = do
    caps <- getNumCapabilities
    csiz <- show . Cache.size <$> getCache_ env
    hits <- intercalate "\n" <$> mapM (show <$>) iss
    (cur, mx) <- ucacheQSize
    let qsiz = "ucache queue" ++ " size: " ++ show cur ++ " / " ++ show mx
    return $
        "capabilities: "
            ++ show caps
            ++ "\n"
            ++ "cache size: "
            ++ csiz
            ++ "\n"
            ++ hits
            ++ "\n"
            ++ qsiz
            ++ "\n"
