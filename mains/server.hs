import Control.Monad ((>=>))
import Data.Char (toUpper)
import Data.List (intercalate)
import Data.Word (Word16)
import Text.Read (readEither)
import System.Console.GetOpt
  (OptDescr (Option), ArgDescr (ReqArg, NoArg), ArgOrder (RequireOrder),
   usageInfo, getOpt)
import System.Environment (getArgs)
import System.IO (Handle, stdout, stderr)

import qualified DNSC.Log as Log
import qualified DNSC.Server as Server

data ServerOptions =
  ServerOptions
  { logFH :: Handle
  , logLevel :: Log.Level
  , disableV6NS :: Bool
  , concurrency :: Int
  , port :: Word16
  , bindHosts :: [String]
  }
  deriving Show

defaultOptions :: ServerOptions
defaultOptions =
  ServerOptions
  { logFH = stdout
  , logLevel = Log.NOTICE
  , disableV6NS = False
  , concurrency = 16
  , port = 53
  , bindHosts = []
  }

descs :: [OptDescr (ServerOptions -> Either String ServerOptions)]
descs =
  [ Option ['h'] ["help"]
    (NoArg $ const $ Left "show help")
    "show this help text"
  , Option [] ["log-output"]
    (ReqArg (\s opts -> parseOutput s >>= \x -> return opts { logFH = x }) $ "{" ++ intercalate "|" (map fst outputs) ++ "}")
    "log output target. default is stdout"
  , Option ['l'] ["log-level"]
    (ReqArg (\s opts -> readEither (map toUpper s) >>= \x -> return opts { logLevel = x }) "{WARN|NOTICE|INFO|DEBUG}")
    "server log-level"
  , Option ['4'] ["disable-v6-ns"]
    (NoArg $ \opts -> return opts { disableV6NS = True })
    "not to query IPv6 NS addresses. default is querying IPv6 NS addresses"
  , Option ['c'] ["concurrency"]
    (ReqArg (\s opts -> readEither s >>= \x -> return opts { concurrency = x }) "POSITIVE_INTEGER")
    "concurrency"
  , Option ['p'] ["port"]
    (ReqArg (\s opts -> readEither s >>= \x -> return opts { port = x }) "PORT_NUMBER")
    "server port number. default is 53"
  ]
  where
    parseOutput s = maybe (Left "unknown log output target") Right $ lookup s outputs
    outputs = [("stdout", stdout), ("stderr", stderr)]

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
run opts = Server.run (logFH opts) (logLevel opts) (disableV6NS opts) (concurrency opts) (fromIntegral $ port opts) (bindHosts opts)

main :: IO ()
main = maybe (return ()) run =<< parseOptions =<< getArgs
