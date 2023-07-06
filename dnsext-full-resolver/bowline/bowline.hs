{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.SEC as DNS
import qualified DNS.Types as DNS
import Data.IP
import Data.Maybe (mapMaybe)
import Data.String (fromString)
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
    (serverLoops, getStatuses) <- getUdpServer udpconf env cnf_udp_port' cnf_bind_addresses
    monLoops <- getMonitor env conf $ concat getStatuses
    race_
        (foldr concurrently_ (return ()) serverLoops)
        (foldr concurrently_ (return ()) monLoops)
  where
    cnf_udp_port' = fromIntegral cnf_udp_port
    udpconf =
        UdpServerConfig
            cnf_udp_pipelines_per_socket
            cnf_udp_workers_per_pipeline
            cnf_udp_queue_size_per_pipeline
            cnf_udp_pipeline_share_queue

main :: IO ()
main = do
    args <- getArgs
    case args of
        [] -> run defaultConfig
        [confFile] -> parseConfig confFile >>= run
        _ -> help

----------------------------------------------------------------

getUdpServer :: UdpServerConfig -> Env -> PortNumber -> [HostName] -> IO ([IO ()], [[IO Status]])
getUdpServer conf env port hosts = do
    hostIPs <- getHostIPs hosts port
    (loopsList, getStatuses) <- unzip <$> mapM (udpServer conf env port) hostIPs
    let pLoops = concat loopsList

    return (pLoops, getStatuses)
  where
    getHostIPs [] p = getAInfoIPs p
    getHostIPs hs _ = return $ map fromString hs

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

----------------------------------------------------------------

getAInfoIPs :: PortNumber -> IO [IP]
getAInfoIPs port = do
    ais <- getAddrInfo Nothing Nothing (Just $ show port)
    let dgramIP AddrInfo{addrAddress = SockAddrInet _ ha} = Just $ IPv4 $ fromHostAddress ha
        dgramIP AddrInfo{addrAddress = SockAddrInet6 _ _ ha6 _} = Just $ IPv6 $ fromHostAddress6 ha6
        dgramIP _ = Nothing
    return $
        mapMaybe dgramIP [ai | ai@AddrInfo{addrSocketType = Datagram} <- ais]
