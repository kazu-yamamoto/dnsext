import Control.Monad ((>=>), guard)
import Data.Char (toUpper)
import Data.List (intercalate)
import Data.Word (Word16)
import Text.Read (readEither)
import System.Console.GetOpt
  (OptDescr (Option), ArgDescr (ReqArg, NoArg), ArgOrder (RequireOrder),
   usageInfo, getOpt)
import System.Environment (getArgs)

import qualified DNSC.Log as Log
import qualified DNSC.Server as Server

data ServerOptions =
  ServerOptions
  { logOutput :: Log.Output
  , logLevel :: Log.Level
  , maxKibiEntries :: Int
  , disableV6NS :: Bool
  , workers :: Int
  , port :: Word16
  , bindHosts :: [String]
  , stdConsole :: Bool
  , fastLogger :: Bool
  }
  deriving Show

defaultOptions :: ServerOptions
defaultOptions =
  ServerOptions
  { logOutput = Log.Stdout
  , logLevel = Log.NOTICE
  , maxKibiEntries = 2 * 1024
  , disableV6NS = False
  , workers = 16
  , port = 53
  , bindHosts = []
  , stdConsole = False
  , fastLogger = False
  }

descs :: [OptDescr (ServerOptions -> Either String ServerOptions)]
descs =
  [ Option ['h'] ["help"]
    (NoArg $ const $ Left "show help")
    "show this help text"
  , Option [] ["log-output"]
    (ReqArg (\s opts -> parseOutput s >>= \x -> return opts { logOutput = x }) $ "{" ++ intercalate "|" (map fst outputs) ++ "}")
    "log output target. default is stdout"
  , Option ['l'] ["log-level"]
    (ReqArg (\s opts -> readEither (map toUpper s) >>= \x -> return opts { logLevel = x }) "{WARN|NOTICE|INFO|DEBUG}")
    "server log-level"
  , Option ['M'] ["max-cache-entries"]
    (ReqArg (\s opts -> readEither s >>= \x -> guard (x > 0) >> return opts { maxKibiEntries = x }) "POSITIVE_INTEGER")
    ("max K-entries in cache (1024 entries per 1). default is " ++ show (maxKibiEntries defaultOptions) ++ " K-entries")
  , Option ['4'] ["disable-v6-ns"]
    (NoArg $ \opts -> return opts { disableV6NS = True })
    "not to query IPv6 NS addresses. default is querying IPv6 NS addresses"
  , Option ['w'] ["workers"]
    (ReqArg (\s opts -> readEither s >>= \x -> return opts { workers = x }) "POSITIVE_INTEGER")
    "workers per host"
  , Option ['p'] ["port"]
    (ReqArg (\s opts -> readEither s >>= \x -> return opts { port = x }) "PORT_NUMBER")
    "server port number. default server-port is 53. monitor port number is server-port + 9970. so default monitor-port is 10023"
  , Option ['s'] ["std-console"]
    (NoArg $ \opts -> return opts { stdConsole = True, logOutput = Log.Stderr })
    "open console using stdin and stdout. also set log-output to stderr"
  , Option ['f'] ["fast-logger"]
    (NoArg $ \opts -> return opts { fastLogger = True })
    ""
  ]
  where
    parseOutput s = maybe (Left "unknown log output target") Right $ lookup s outputs
    outputs = [("stdout", Log.Stdout), ("stderr", Log.Stderr)]

help :: IO ()
help =
  putStr $ usageInfo
  "cache-server [options] [BIND_HOSTNAMES]"
  descs

parseOptions :: [String] -> IO (Maybe ServerOptions)
parseOptions args
  | not (null errs)  =  mapM putStrLn errs *> return Nothing
  | otherwise        =  either helpOnLeft (return . Just) $ do
      opt <- foldr (>=>) return ars defaultOptions
      return opt { bindHosts = hosts }
  where
    (ars, hosts, errs) = getOpt RequireOrder descs args
    helpOnLeft e = putStrLn e *> help *> return Nothing

run :: ServerOptions -> IO ()
run opts = Server.run (fastLogger opts) (logOutput opts) (logLevel opts) (maxKibiEntries opts * 1024) (disableV6NS opts) (workers opts) (fromIntegral $ port opts) (bindHosts opts) (stdConsole opts)

main :: IO ()
main = maybe (return ()) run =<< parseOptions =<< getArgs
