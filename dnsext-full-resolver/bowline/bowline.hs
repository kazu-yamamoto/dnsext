{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent (forkIO, killThread, getNumCapabilities, threadDelay)
import Control.Concurrent.STM
import Control.Monad (when, guard)
import DNS.Cache.Iterative (Env (..))
import qualified DNS.Cache.Iterative as Iterative
import DNS.Cache.Server
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.SEC as DNS
import qualified DNS.SVCB as DNS
import qualified DNS.Types as DNS
import Data.List (intercalate)
import Network.TLS (Credentials (..), credentialLoadX509)
import System.Environment (getArgs)
import UnliftIO (concurrently_, race_)

import Config
import DNSTAP
import Manage
import qualified Monitor as Mon
import WebAPI

----------------------------------------------------------------

help :: IO ()
help = putStrLn "bowline [<confFile>]"

----------------------------------------------------------------

run :: IO Config -> IO ()
run readConfig = newManage >>= go
  where
    go mng = do
        readConfig >>= runConfig mng
        cont <- getReloadAndClear mng
        when cont $ do
            putStrLn "reloading..."
            go mng

runConfig :: Manage -> Config -> IO ()
runConfig mng conf@Config{..} = do
    (writer, putDNSTAP) <- newDnstapWriter conf
    (logger, putLines, flush) <- Log.new cnf_log_output cnf_log_level
    tid <- forkIO logger
    env <- getEnv conf putLines putDNSTAP
    creds <-
        if cnf_tls || cnf_quic || cnf_h2 || cnf_h3
            then do
                Right cred@(!_cc, !_priv) <- credentialLoadX509 cnf_cert_file cnf_key_file
                return $ Credentials [cred]
            else return $ Credentials []
    let trans =
            [ (cnf_udp, udpServer udpconf, cnf_udp_port)
            , (cnf_tcp, tcpServer vcconf, cnf_tcp_port)
            , (cnf_h2c, http2cServer vcconf, cnf_h2c_port)
            , (cnf_h2, http2Server creds vcconf, cnf_h2_port)
            , (cnf_h3, http3Server creds vcconf, cnf_h3_port)
            , (cnf_tls, tlsServer creds vcconf, cnf_tls_port)
            , (cnf_quic, quicServer creds vcconf, cnf_quic_port)
            ]
    (servers, statuses) <- unzip <$> mapM (getServers env cnf_dns_addrs) trans
    qRef <- newTVarIO False
    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
        mng' = mng { getStatus = getStatus' env (concat statuses) ucacheQSize
                   , quitServer = atomically $ writeTVar qRef True
                   , waitQuit = readTVar qRef >>= guard
                   }
        api = runAPI cnf_webapi_addr cnf_webapi_port mng'
    monitor <- getMonitor env conf mng'
    race_ (conc (api : writer : concat servers)) (conc monitor)
    threadDelay 100000
    killThread tid
    flush
  where
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
    (xss, yss) <- unzip <$> mapM (server env port) hosts
    let xs = concat xss
        ys = concat yss
    return (xs, ys)
  where
    port = fromIntegral port'

----------------------------------------------------------------

getMonitor :: Env -> Config -> Manage-> IO [IO ()]
getMonitor env conf mng = do
    logLines_ env Log.WARN Nothing $ map ("params: " ++) $ showConfig conf
    Mon.monitor conf env mng

----------------------------------------------------------------

getEnv :: Config -> Log.PutLines -> (Message -> IO ()) -> IO Env
getEnv Config{..} putLines putDNSTAP = do
    tcache@(getSec, getTimeStr) <- TimeCache.new
    let cacheConf = Cache.MemoConf cnf_cache_size 1800 memoActions
          where
            memoLogLn msg = do
                tstr <- getTimeStr
                putLines Log.WARN Nothing [tstr $ ": " ++ msg]
            memoActions = Cache.MemoActions memoLogLn getSec
    updateCache <- Iterative.getUpdateCache cacheConf
    Iterative.newEnv putLines putDNSTAP cnf_disable_v6_ns updateCache tcache

----------------------------------------------------------------

getStatus' :: Env -> [IO Status] -> IO (Int, Int) -> IO String
getStatus' env iss ucacheQSize = do
    caps <- getNumCapabilities
    csiz <- show . Cache.size <$> getCache_ env
    hits <- intercalate "\n" <$>  mapM (\action -> show <$> action) iss
    (cur, mx) <- ucacheQSize
    let qsiz = "ucache queue" ++ " size: " ++ show cur ++ " / " ++ show mx
    return $ "capabilities: " ++ show caps ++
             "cache size: " ++ csiz ++
             hits ++ "\n" ++
             qsiz
