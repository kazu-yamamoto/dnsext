{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.SEC as DNS
import qualified DNS.Types as DNS
import Network.Socket
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
    (udpServers, udpStatus) <- getServers (udpServer udpconf env) cnf_udp_port' cnf_bind_addresses
    (tcpServers, tcpStatus) <- getServers (tcpServer tcpconf env) cnf_tcp_port' cnf_bind_addresses
    (h2Servers, h2Status) <- getServers (http2Server http2conf env) 10080 cnf_bind_addresses
    let servers = udpServers ++ tcpServers ++ h2Servers
    monitor <- getMonitor env conf (udpStatus ++ tcpStatus ++ h2Status)
    race_
        (foldr concurrently_ (return ()) servers)
        (foldr concurrently_ (return ()) monitor)
  where
    cnf_udp_port' = fromIntegral cnf_udp_port
    cnf_tcp_port' = fromIntegral cnf_tcp_port
    udpconf =
        UdpServerConfig
            cnf_udp_pipelines_per_socket
            cnf_udp_workers_per_pipeline
            cnf_udp_queue_size_per_pipeline
            cnf_udp_pipeline_share_queue
    tcpconf =
        TcpServerConfig
            cnf_tcp_idle_timeout
    http2conf =
        Http2ServerConfig 30000000

main :: IO ()
main = do
    args <- getArgs
    case args of
        [] -> run defaultConfig
        [confFile] -> parseConfig confFile >>= run
        _ -> help

----------------------------------------------------------------

getServers
    :: (PortNumber -> HostName -> IO ([IO ()], [IO Status]))
    -> PortNumber
    -> [HostName]
    -> IO ([IO ()], [IO Status])
getServers server port hosts = do
    (xss, yss) <- unzip <$> mapM (server port) hosts
    let xs = concat xss
        ys = concat yss
    return (xs, ys)

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
