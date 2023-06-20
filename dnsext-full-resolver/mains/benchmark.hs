{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Monad (unless, (>=>))
import System.Console.GetOpt (
    ArgDescr (NoArg, ReqArg),
    ArgOrder (RequireOrder),
    OptDescr (Option),
    getOpt,
    usageInfo,
 )
import System.Environment (getArgs)
import Text.Read (readEither)

import qualified DNS.Cache.Server as Server
import qualified DNS.Log as Log

data BenchmarkOptions = BenchmarkOptions
    { logOutput :: Log.Output
    , logLevel :: Log.Level
    , maxKibiEntries :: Int
    , noopMode :: Bool
    , gplotMode :: Bool
    , workers :: Int
    , qsizePerWorker :: Int
    , requests :: Int
    }

defaultOptions :: BenchmarkOptions
defaultOptions =
    BenchmarkOptions
        { logOutput = Log.Stdout
        , logLevel = Log.WARN
        , maxKibiEntries = 2 * 1024
        , noopMode = False
        , gplotMode = False
        , workers = 2
        , qsizePerWorker = 16
        , requests = 512 * 1024
        }

descs :: [OptDescr (BenchmarkOptions -> Either String BenchmarkOptions)]
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
        ['w']
        ["workers"]
        ( ReqArg
            ( \s opts ->
                readIntWith (> 0) "workers. not positive" s >>= \x -> return opts{workers = x}
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

parseOptions :: [String] -> IO (Maybe BenchmarkOptions)
parseOptions args
    | not (null errs) = mapM putStrLn errs *> return Nothing
    | otherwise = either helpOnLeft (return . Just) $ do
        opt <- foldr (>=>) return ars defaultOptions
        return opt
  where
    (ars, _rest, errs) = getOpt RequireOrder descs args
    helpOnLeft e = putStrLn e *> help *> return Nothing

run :: BenchmarkOptions -> IO ()
run BenchmarkOptions{..} =
    Server.workerBenchmark
        conf
        noopMode
        gplotMode
        requests
  where
    conf =
        Server.Config
            logOutput
            logLevel
            (2 * 1024 * 1024)
            False
            workers
            qsizePerWorker
            True

main :: IO ()
main = maybe (return ()) run =<< parseOptions =<< getArgs
