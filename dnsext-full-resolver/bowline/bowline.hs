{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.SEC as DNS
import qualified DNS.Types as DNS
import Network.Socket
import Network.TLS (Credentials (..), credentialLoadX509)
import System.Environment (getArgs)
import UnliftIO (concurrently_, race_)

import DNS.Cache.Iterative (Env (..))
import qualified DNS.Cache.Iterative as Iterative
import DNS.Cache.Server
import qualified DNS.Cache.TimeCache as TimeCache

import Config
import qualified Monitor as Mon

----------------------------------------------------------------

help :: IO ()
help = putStrLn "bowline [<confFile>]"

----------------------------------------------------------------

run :: Config -> IO ()
run conf@Config{..} = do
    DNS.runInitIO DNS.addResourceDataForDNSSEC
    env <- getEnv conf
    creds <-
        if cnf_tls || cnf_quic || cnf_h2 || cnf_h3
            then do
                Right cred@(!_cc, !_priv) <- credentialLoadX509 cnf_cert_file cnf_key_file
                return $ Credentials [cred]
            else return $ Credentials []
    let trans =
            [ (cnf_udp, udpServer udpconf, cnf_udp_port)
            , (cnf_tcp, tcpServer tcpconf, cnf_tcp_port)
            , (cnf_h2c, http2cServer h2cconf, cnf_h2c_port)
            , (cnf_h2, http2Server creds h2conf, cnf_h2_port)
            ]
    (servers, statuses) <- unzip <$> mapM (getServers env cnf_addrs) trans
    monitor <- getMonitor env conf $ concat statuses
    race_ (conc $ concat servers) (conc monitor)
  where
    conc = foldr concurrently_ $ return ()
    udpconf =
        UdpServerConfig
            cnf_udp_pipelines_per_socket
            cnf_udp_workers_per_pipeline
            cnf_udp_queue_size_per_pipeline
            cnf_udp_pipeline_share_queue
    tcpconf =
        TcpServerConfig
            cnf_tcp_idle_timeout
    h2cconf =
        Http2cServerConfig
            cnf_h2c_idle_timeout
    h2conf =
        Http2ServerConfig
            cnf_h2_idle_timeout

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
    Mon.monitor conf env (qsizes, ucacheQSize, logQSize_ env) (logTerminate_ env)

----------------------------------------------------------------

getEnv :: Config -> IO Env
getEnv Config{..} = do
    logTriple@(putLines, _, _) <- Log.new cnf_log_output cnf_log_level
    tcache@(getSec, getTimeStr) <- TimeCache.new
    let cacheConf = Cache.MemoConf cnf_cache_size 1800 memoActions
          where
            memoLogLn msg = do
                tstr <- getTimeStr
                putLines Log.WARN Nothing [tstr $ ": " ++ msg]
            memoActions = Cache.MemoActions memoLogLn getSec
    updateCache <- Iterative.getUpdateCache cacheConf
    Iterative.newEnv logTriple cnf_disable_v6_ns updateCache tcache
