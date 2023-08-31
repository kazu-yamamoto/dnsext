{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent (forkIO, killThread)
import DNS.Cache.Iterative (Env (..))
import qualified DNS.Cache.Iterative as Iterative
import DNS.Cache.Server
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.SEC as DNS
import qualified DNS.SVCB as DNS
import qualified DNS.Types as DNS
import Network.TLS (Credentials (..), credentialLoadX509)
import System.Environment (getArgs)
import UnliftIO (concurrently_, race_)

import Config
import DNSTAP
import qualified Monitor as Mon

----------------------------------------------------------------

help :: IO ()
help = putStrLn "bowline [<confFile>]"

----------------------------------------------------------------

run :: Config -> IO ()
run conf@Config{..} = do
    DNS.runInitIO $ do
        DNS.addResourceDataForDNSSEC
        DNS.addResourceDataForSVCB
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
    (servers, statuses) <- unzip <$> mapM (getServers env cnf_addrs) trans
    monitor <- getMonitor env conf $ concat statuses
    race_ (conc (writer : concat servers)) (conc monitor)
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
    args <- getArgs
    case args of
        [] -> run defaultConfig
        [confFile] -> parseConfig confFile >>= run
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

getMonitor :: Env -> Config -> [IO Status] -> IO [IO ()]
getMonitor env conf qsizes = do
    logLines_ env Log.WARN Nothing $ map ("params: " ++) $ showConfig conf

    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
    Mon.monitor conf env (qsizes, ucacheQSize)

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
