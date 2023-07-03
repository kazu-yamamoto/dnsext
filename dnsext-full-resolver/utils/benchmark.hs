{-# LANGUAGE ParallelListComp #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent (forkIO, getNumCapabilities)
import Control.DeepSeq (deepseq)
import Control.Monad (replicateM, unless, (>=>))
import qualified DNS.Types as DNS
import qualified DNS.Types.Encode as DNS
import Data.ByteString (ByteString)
import Data.String (fromString)
import Data.Time (NominalDiffTime, diffUTCTime, getCurrentTime)
import System.Console.GetOpt (
    ArgDescr (NoArg, ReqArg),
    ArgOrder (RequireOrder),
    OptDescr (Option),
    getOpt,
    usageInfo,
 )
import System.Environment (getArgs)
import Text.Read (readEither)
import UnliftIO (concurrently_)

import DNS.Cache.Iterative (Env (..))
import qualified DNS.Cache.Iterative as Iterative
import DNS.Cache.Server.Bench
import qualified DNS.Cache.TimeCache as TimeCache
import qualified DNS.Do53.Memo as Cache
import qualified DNS.Log as Log

data Config = Config
    { logOutput :: Log.Output
    , logLevel :: Log.Level
    , maxCacheSize :: Int
    , noopMode :: Bool
    , gplotMode :: Bool
    , pipelines :: Int
    , qsizePerWorker :: Int
    , requests :: Int
    }

defaultOptions :: Config
defaultOptions =
    Config
        { logOutput = Log.Stdout
        , logLevel = Log.WARN
        , maxCacheSize = 2 * 1024
        , noopMode = False
        , gplotMode = False
        , pipelines = 2
        , qsizePerWorker = 16
        , requests = 512 * 1024
        }

descs :: [OptDescr (Config -> Either String Config)]
descs =
    [ Option
        ['h']
        ["help"]
        (NoArg $ const $ Left "show help")
        "show this help text"
    , -- , Option [] ["log-output"]
      --   (ReqArg (\s opts -> parseOutput s >>= \x -> return opts { logOutput = x }) $ "{" ++ intercalate "|" (map fst outputs) ++ "}")
      --   "log output target. default is stdout"
      -- , Option ['l'] ["log-level"]
      --   (ReqArg (\s opts -> readEither (map toUpper s) >>= \x -> return opts { logLevel = x }) "{WARN|NOTICE|INFO|DEBUG}")
      --   "server log-level"
      -- , Option ['M'] ["max-cache-entries"]
      --   (ReqArg (\s opts -> readIntWith (> 0) "max-cache-entries. not positive size" s >>= \x -> return opts { maxKibiEntries = x }) "POSITIVE_INTEGER")
      --   ("max K-entries in cache (1024 entries per 1). default is " ++ show (maxKibiEntries defaultOptions) ++ " K-entries")
      Option
        []
        ["noop"]
        (NoArg $ \opts -> return opts{noopMode = True})
        "No-op mode"
    , Option
        []
        ["plot"]
        (NoArg $ \opts -> return opts{gplotMode = True})
        "output for GNUplot"
    , Option
        ['p']
        ["pipelines"]
        ( ReqArg
            ( \s opts ->
                readIntWith (> 0) "pipelines. not positive" s >>= \x -> return opts{pipelines = x}
            )
            "POSITIVE_INTEGER"
        )
        "workers per host. default is 2"
    , -- , Option [] ["no-shared-queue"]
      --   (NoArg $ \opts -> return opts { workerSharedQueue = False })
      --   "not share request queue and response queue in worker threads"
      Option
        []
        ["per-worker"]
        ( ReqArg
            ( \s opts ->
                readIntWith (>= 0) "per-worker. negative not allowed" s >>= \x -> return opts{qsizePerWorker = x}
            )
            "POSITIVE_INTEGER"
        )
        "queue size per worker. default is 16. positive integer or 0. 0 means not limited size queue"
    , Option
        ['r']
        ["requests"]
        ( ReqArg
            ( \s opts ->
                readIntWith (> 0) "requests. not positive" s >>= \x -> return opts{requests = x}
            )
            "POSITIVE_INTEGER"
        )
        "requests count. default is 512 * 1024"
    ]
  where
    readIntWith p em s = do
        x <- readEither s :: Either String Int
        unless (p x) $ Left $ em ++ ": " ++ show x
        return $ fromIntegral x

-- parseOutput s = maybe (Left "unknown log output target") Right $ lookup s outputs
-- outputs = [("stdout", Log.Stdout), ("stderr", Log.Stderr)]

help :: IO ()
help =
    putStr $
        usageInfo
            "benchmark [options]"
            descs

parseOptions :: [String] -> IO (Maybe Config)
parseOptions args
    | not (null errs) = mapM putStrLn errs *> return Nothing
    | otherwise = either helpOnLeft (return . Just) $ do
        opt <- foldr (>=>) return ars defaultOptions
        return opt
  where
    (ars, _rest, errs) = getOpt RequireOrder descs args
    helpOnLeft e = putStrLn e *> help *> return Nothing

run :: Config -> IO ()
run conf@Config{..} = runBenchmark conf udpconf noopMode gplotMode requests
  where
    udpconf =
        UdpServerConfig
            pipelines
            8
            qsizePerWorker
            True

main :: IO ()
main = maybe (return ()) run =<< parseOptions =<< getArgs

runBenchmark
    :: Config
    -> UdpServerConfig
    -> Bool
    -- ^ No operation or not
    -> Bool
    -- ^ Gnuplot mode or not
    -> Int
    -- ^ Request size
    -> IO ()
runBenchmark conf udpconf@UdpServerConfig{..} noop gplot size = do
    env <- getEnv conf

    (workers, enqueueReq, dequeueResp) <- benchServer udpconf env noop
    _ <- forkIO $ foldr concurrently_ (return ()) $ concat workers

    let (initD, ds) = splitAt 4 $ take (4 + size) benchQueries
    ds `deepseq` return ()

    -----
    _ <- runQueries initD enqueueReq dequeueResp
    before <- getCurrentTime
    _ <- runQueries ds enqueueReq dequeueResp
    after <- getCurrentTime

    let elapsed = after `diffUTCTime` before
        toDouble = fromRational . toRational :: NominalDiffTime -> Double
        rate = toDouble $ fromIntegral size / after `diffUTCTime` before

    if gplot
        then do
            putStrLn $ unwords [show udp_pipelines_per_socket, show rate]
        else do
            putStrLn . ("capabilities: " ++) . show =<< getNumCapabilities
            putStrLn $ "pipelines: " ++ show udp_pipelines_per_socket
            putStrLn $ "qsizePerWorker: " ++ show udp_queue_size_per_worker
            putStrLn . ("cache size: " ++) . show . Cache.size =<< getCache_ env
            putStrLn $ "requests: " ++ show size
            putStrLn $ "elapsed: " ++ show elapsed
            putStrLn $ "rate: " ++ show rate

getEnv :: Config -> IO Env
getEnv Config{..} = do
    logTripble@(putLines, _, _) <- Log.new logOutput logLevel
    tcache@(getSec, _) <- TimeCache.new
    let cacheConf = Cache.MemoConf maxCacheSize 1800 memoActions
          where
            memoLogLn = putLines Log.WARN Nothing . (: [])
            memoActions = Cache.MemoActions memoLogLn getSec
    updateCache <- Iterative.getUpdateCache cacheConf
    Iterative.newEnv logTripble False updateCache tcache

runQueries :: [a1] -> ((a1, ()) -> IO a2) -> IO a3 -> IO [a3]
runQueries qs enqueueReq dequeueResp = do
    _ <- forkIO $ sequence_ [enqueueReq (q, ()) | q <- qs]
    replicateM len dequeueResp
  where
    len = length qs

benchQueries :: [ByteString]
benchQueries =
    [ DNS.encode $ setId mid rootA {- TODO: seq ByteString ? -}
    | mid <- cycle [0 .. maxBound]
    | rootA <- cycle rootAs
    ]
  where
    setId mid qm = qm{DNS.header = dh{DNS.identifier = mid}}
    dh = DNS.header DNS.defaultQuery
    rootAs =
        [ DNS.defaultQuery
            { DNS.question = [DNS.Question (fromString name) DNS.A DNS.classIN]
            }
        | c1 <- ["a", "b", "c", "d"]
        , let name = c1 ++ ".root-servers.net."
        ]
