{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent (getNumCapabilities)
import Control.Monad (unless, (>=>))
import qualified DNS.Cache.Iterative as Iterative
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log
import qualified DNS.SEC as DNS
import qualified DNS.Types as DNS
import Data.Char (toUpper)
import Data.IP
import Data.List (intercalate)
import Data.Maybe (mapMaybe)
import Data.String (fromString)
import Data.Word (Word16)
import Network.Socket
import System.Console.GetOpt (
    ArgDescr (NoArg, ReqArg),
    ArgOrder (RequireOrder),
    OptDescr (Option),
    getOpt,
    usageInfo,
 )
import System.Environment (getArgs)
import Text.Read (readEither)
import UnliftIO (concurrently_, race_)

import DNS.Cache.Iterative (Env (..))
import DNS.Cache.Server

import qualified Monitor as Mon

----------------------------------------------------------------

data Config = Config
    { logOutput :: Log.Output
    , logLevel :: Log.Level
    , maxCacheSize :: Int
    , disableV6NS :: Bool
    , workers :: Int
    , workerSharedQueue :: Bool
    , qsizePerWorker :: Int
    , port :: Word16
    , bindHosts :: [String]
    , stdConsole :: Bool
    }

defaultConfig :: Config
defaultConfig =
    Config
        { logOutput = Log.Stdout
        , logLevel = Log.WARN
        , maxCacheSize = 2 * 1024
        , disableV6NS = False
        , workers = 2
        , workerSharedQueue = True
        , qsizePerWorker = 16
        , port = 53
        , bindHosts = []
        , stdConsole = False
        }

----------------------------------------------------------------

descs :: [OptDescr (Config -> Either String Config)]
descs =
    [ Option
        ['h']
        ["help"]
        (NoArg $ const $ Left "show help")
        "show this help text"
    , Option
        []
        ["log-output"]
        ( ReqArg (\s opts -> parseOutput s >>= \x -> return opts{logOutput = x}) $
            "{" ++ intercalate "|" (map fst outputs) ++ "}"
        )
        "log output target. default is stdout"
    , Option
        ['l']
        ["log-level"]
        ( ReqArg
            (\s opts -> readEither (map toUpper s) >>= \x -> return opts{logLevel = x})
            "{WARN|NOTICE|INFO|DEBUG}"
        )
        "server log-level"
    , Option
        ['M']
        ["max-cache-entries"]
        ( ReqArg
            ( \s opts ->
                readIntWith (> 0) "max-cache-entries. not positive size" s >>= \x -> return opts{maxCacheSize = x}
            )
            "POSITIVE_INTEGER"
        )
        ( "max K-entries in cache (1024 entries per 1). default is "
            ++ show (maxCacheSize defaultConfig)
            ++ " K-entries"
        )
    , Option
        ['4']
        ["disable-v6-ns"]
        (NoArg $ \opts -> return opts{disableV6NS = True})
        "not to query IPv6 NS addresses. default is querying IPv6 NS addresses"
    , Option
        ['w']
        ["workers"]
        ( ReqArg
            ( \s opts ->
                readIntWith (> 0) "workers. not positive" s >>= \x -> return opts{workers = x}
            )
            "POSITIVE_INTEGER"
        )
        "workers per host. default is 2"
    , Option
        []
        ["no-shared-queue"]
        (NoArg $ \opts -> return opts{workerSharedQueue = False})
        "not share request queue and response queue in worker threads"
    , Option
        []
        ["per-worker"]
        ( ReqArg
            ( \s opts ->
                readIntWith (>= 0) "per-worker. not positive" s >>= \x -> return opts{qsizePerWorker = x}
            )
            "POSITIVE_INTEGER"
        )
        "queue size per worker. default is 16. positive integer or 0. 0 means not limited size queue"
    , Option
        ['p']
        ["port"]
        ( ReqArg
            ( \s opts ->
                readIntWith (>= 0) "port. non-negative is required" s >>= \x -> return opts{port = x}
            )
            "PORT_NUMBER"
        )
        "server port number. default server-port is 53. monitor port number is server-port + 9970. so default monitor-port is 10023.\nyou can connect to the monitor with `telnet localhost <monitor port>`. for more information, connect to monitor and type `help<Enter>`."
    , Option
        ['s']
        ["std-console"]
        (NoArg $ \opts -> return opts{stdConsole = True, logOutput = Log.Stderr})
        "open console using stdin and stdout. also set log-output to stderr"
    ]
  where
    readIntWith p em s = do
        x <- readEither s :: Either String Int
        unless (p x) $ Left $ em ++ ": " ++ show x
        return $ fromIntegral x
    parseOutput s = maybe (Left "unknown log output target") Right $ lookup s outputs
    outputs = [("stdout", Log.Stdout), ("stderr", Log.Stderr)]

----------------------------------------------------------------

help :: IO ()
help =
    putStr $
        usageInfo
            "cache-server [options] [BIND_HOSTNAMES]"
            descs

----------------------------------------------------------------

parseOptions :: [String] -> IO (Maybe Config)
parseOptions args
    | not (null errs) = mapM putStrLn errs *> return Nothing
    | otherwise = either helpOnLeft (return . Just) $ do
        opt <- foldr (>=>) return ars defaultConfig
        return opt{bindHosts = hosts}
  where
    (ars, hosts, errs) = getOpt RequireOrder descs args
    helpOnLeft e = putStrLn e *> help *> return Nothing

----------------------------------------------------------------

run :: Config -> IO ()
run conf@Config{..} = do
    DNS.runInitIO DNS.addResourceDataForDNSSEC
    env <- getEnv conf
    (serverLoops, qsizes) <- getUdpServer env udpconf port' bindHosts
    monLoops <- getMonitor env conf port' bindHosts stdConsole qsizes
    race_
        (foldr concurrently_ (return ()) serverLoops)
        (foldr concurrently_ (return ()) monLoops)
  where
    port' = fromIntegral port
    udpconf =
        UdpServerConfig
            workers
            qsizePerWorker
            workerSharedQueue

main :: IO ()
main = maybe (return ()) run =<< parseOptions =<< getArgs

----------------------------------------------------------------

getUdpServer :: Env -> UdpServerConfig -> PortNumber -> [HostName] -> IO ([IO ()], [PLStatus])
getUdpServer env conf port hosts = do
    hostIPs <- getHostIPs hosts port
    (loopsList, qsizes) <- unzip <$> mapM (udpServer conf env port) hostIPs
    let pLoops = concat loopsList

    return (pLoops, qsizes)
  where
    getHostIPs [] p = getAInfoIPs p
    getHostIPs hs _ = return $ map fromString hs

----------------------------------------------------------------

getMonitor :: Env -> Config -> PortNumber -> [HostName] -> Bool -> [PLStatus] -> IO [IO ()]
getMonitor env Config{..} port_ hosts stdConsole_ qsizes = do
    caps <- getNumCapabilities
    let params = mkParams caps

    logLines_ env Log.WARN Nothing $ map ("params: " ++) $ Mon.showParams params

    let ucacheQSize = return (0, 0 {- TODO: update ServerMonitor to drop -})
    Mon.monitor stdConsole_ params env (qsizes, ucacheQSize, logQSize_ env) (logTerminate_ env)
  where
    mkParams caps =
        Mon.makeParams
            caps
            logOutput
            logLevel
            maxCacheSize
            disableV6NS
            2 -- fixme
            workerSharedQueue
            qsizePerWorker
            port_
            hosts

----------------------------------------------------------------

getEnv :: Config -> IO Env
getEnv Config{..} = do
    logTriple@(putLines, _, _) <- Log.new logOutput logLevel
    tcache@(getSec, getTimeStr) <- TimeCache.new
    let cacheConf = Cache.MemoConf maxCacheSize 1800 memoActions
          where
            memoLogLn msg = do
                tstr <- getTimeStr
                putLines Log.WARN Nothing [tstr $ ": " ++ msg]
            memoActions = Cache.MemoActions memoLogLn getSec
    updateCache <- Iterative.getUpdateCache cacheConf
    Iterative.newEnv logTriple disableV6NS updateCache tcache

----------------------------------------------------------------

getAInfoIPs :: PortNumber -> IO [IP]
getAInfoIPs port = do
    ais <- getAddrInfo Nothing Nothing (Just $ show port)
    let dgramIP AddrInfo{addrAddress = SockAddrInet _ ha} = Just $ IPv4 $ fromHostAddress ha
        dgramIP AddrInfo{addrAddress = SockAddrInet6 _ _ ha6 _} = Just $ IPv6 $ fromHostAddress6 ha6
        dgramIP _ = Nothing
    return $
        mapMaybe dgramIP [ai | ai@AddrInfo{addrSocketType = Datagram} <- ais]
