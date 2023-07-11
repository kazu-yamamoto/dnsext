{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeSynonymInstances #-}

module Config (
    Config (..),
    defaultConfig,
    parseConfig,
    showConfig,
) where

import qualified DNS.Log as Log
import Data.Char (toUpper)
import Data.List.Split (splitOn)
import Text.Parsec
import Text.Parsec.ByteString.Lazy

import Parser

data Config = Config
    { cnf_log_output :: Log.Output
    , cnf_log_level :: Log.Level
    , cnf_cert_file :: FilePath
    , cnf_key_file :: FilePath
    , cnf_cache_size :: Int
    , cnf_disable_v6_ns :: Bool
    , cnf_udp :: Bool
    , cnf_udp_pipelines_per_socket :: Int
    , cnf_udp_workers_per_pipeline :: Int
    , cnf_udp_queue_size_per_pipeline :: Int
    , cnf_udp_pipeline_share_queue :: Bool
    , cnf_udp_port :: Int
    , cnf_tcp :: Bool
    , cnf_tcp_idle_timeout :: Int
    , cnf_tcp_port :: Int
    , cnf_tls :: Bool
    , cnf_tls_idle_timeout :: Int
    , cnf_tls_port :: Int
    , cnf_quic :: Bool
    , cnf_quic_idle_timeout :: Int
    , cnf_quic_port :: Int
    , cnf_h2c :: Bool
    , cnf_h2c_idle_timeout :: Int
    , cnf_h2c_port :: Int
    , cnf_h2 :: Bool
    , cnf_h2_idle_timeout :: Int
    , cnf_h2_port :: Int
    , cnf_h3 :: Bool
    , cnf_h3_idle_timeout :: Int
    , cnf_h3_port :: Int
    , cnf_monitor_port :: Int
    , cnf_addrs :: [String]
    , cnf_monitor_stdio :: Bool
    }
    deriving (Show)

defaultConfig :: Config
defaultConfig =
    Config
        { cnf_log_output = Log.Stdout
        , cnf_log_level = Log.WARN
        , cnf_cert_file = "fullchain.pem"
        , cnf_key_file = "privkey.pem"
        , cnf_cache_size = 2 * 1024
        , cnf_disable_v6_ns = False
        , cnf_udp = True
        , cnf_udp_pipelines_per_socket = 2
        , cnf_udp_workers_per_pipeline = 8
        , cnf_udp_pipeline_share_queue = True
        , cnf_udp_queue_size_per_pipeline = 16
        , cnf_udp_port = 53
        , cnf_tcp = True
        , cnf_tcp_idle_timeout = 30
        , cnf_tcp_port = 53
        , cnf_tls = True
        , cnf_tls_idle_timeout = 30
        , cnf_tls_port = 853
        , cnf_quic = True
        , cnf_quic_idle_timeout = 30
        , cnf_quic_port = 853
        , cnf_h2c = True
        , cnf_h2c_idle_timeout = 30
        , cnf_h2c_port = 80
        , cnf_h2 = True
        , cnf_h2_idle_timeout = 30
        , cnf_h2_port = 443
        , cnf_h3 = True
        , cnf_h3_idle_timeout = 30
        , cnf_h3_port = 443
        , cnf_monitor_port = 10023
        , cnf_addrs = []
        , cnf_monitor_stdio = False
        }

----------------------------------------------------------------

showConfig :: Config -> [String]
showConfig conf =
    [ -- field "capabilities" numCapabilities
      field'_ "log output" (showOut . cnf_log_output)
    , field' "log level" cnf_log_level
    , field' "max cache size" cnf_cache_size
    , field' "disable queries to IPv6 NS" cnf_disable_v6_ns
    , field' "pipelines per socket" cnf_udp_pipelines_per_socket
    , field' "worker shared queue" cnf_udp_pipeline_share_queue
    , field' "queue size per worker" cnf_udp_queue_size_per_pipeline
    , field' "DNS port" cnf_udp_port
    , field' "Monitor port" cnf_monitor_port
    ]
        ++ if null hosts
            then ["DNS host list: null"]
            else "DNS host list:" : map ("DNS host: " ++) hosts
  where
    field'_ label' toS = label' ++ ": " ++ toS conf
    field' label' get = field'_ label' (show . get)
    showOut Log.Stdout = "stdout"
    showOut Log.Stderr = "stderr"
    showOut _ = "rotate file"
    hosts = cnf_addrs conf

----------------------------------------------------------------

-- | Parsing a configuration file to get an 'Config'.
parseConfig :: FilePath -> IO Config
parseConfig file = makeConfig defaultConfig <$> readConfig file

makeConfig :: Config -> [Conf] -> Config
makeConfig def conf =
    Config
        { cnf_log_output = Log.Stdout -- fixme
        , cnf_log_level = get "log-level" cnf_log_level
        , cnf_cert_file = get "cert-file" cnf_cert_file
        , cnf_key_file = get "key-file" cnf_key_file
        , cnf_cache_size = get "cache-size" cnf_cache_size
        , cnf_disable_v6_ns = get "disable-v6-ns" cnf_disable_v6_ns
        , cnf_udp = get "udp" cnf_udp
        , cnf_udp_pipelines_per_socket = get "udp-pipelines-per-socket" cnf_udp_pipelines_per_socket
        , cnf_udp_workers_per_pipeline = get "udp-workers-per-pipeline" cnf_udp_workers_per_pipeline
        , cnf_udp_queue_size_per_pipeline = get "udp-queue-size-per-pipeline" cnf_udp_queue_size_per_pipeline
        , cnf_udp_pipeline_share_queue = get "udp-pipeline-share-queue" cnf_udp_pipeline_share_queue
        , cnf_udp_port = get "udp-port" cnf_udp_port
        , cnf_tcp = get "tcp" cnf_tcp
        , cnf_tcp_idle_timeout = get "tcp-idle-timeout" cnf_tcp_idle_timeout
        , cnf_tcp_port = get "tcp-port" cnf_tcp_port
        , cnf_tls = get "tls" cnf_tls
        , cnf_tls_idle_timeout = get "tls-idle-timeout" cnf_tls_idle_timeout
        , cnf_tls_port = get "tls-port" cnf_tls_port
        , cnf_quic = get "quic" cnf_quic
        , cnf_quic_idle_timeout = get "quic-idle-timeout" cnf_quic_idle_timeout
        , cnf_quic_port = get "quic-port" cnf_quic_port
        , cnf_h2c = get "h2c" cnf_h2c
        , cnf_h2c_idle_timeout = get "h2c-idle-timeout" cnf_h2c_idle_timeout
        , cnf_h2c_port = get "h2c-port" cnf_h2c_port
        , cnf_h2 = get "h2" cnf_h2
        , cnf_h2_idle_timeout = get "h2-idle-timeout" cnf_h2_idle_timeout
        , cnf_h2_port = get "h2-port" cnf_h2_port
        , cnf_h3 = get "h3" cnf_h3
        , cnf_h3_idle_timeout = get "h3-idle-timeout" cnf_h3_idle_timeout
        , cnf_h3_port = get "h3-port" cnf_h3_port
        , cnf_monitor_port = get "monitor-port" cnf_monitor_port
        , cnf_addrs = get "addrs" cnf_addrs
        , cnf_monitor_stdio = get "monitor-stdio" cnf_monitor_stdio
        }
  where
    get k func = maybe (func def) fromConf $ lookup k conf

----------------------------------------------------------------

type Conf = (String, ConfValue)

data ConfValue = CV_Int Int | CV_Bool Bool | CV_String String deriving (Eq, Show)

class FromConf a where
    fromConf :: ConfValue -> a

instance FromConf Int where
    fromConf (CV_Int n) = n
    fromConf _ = error "fromConf int"

instance FromConf Bool where
    fromConf (CV_Bool b) = b
    fromConf _ = error "fromConf bool"

instance FromConf String where
    fromConf (CV_String s) = s
    fromConf _ = error "fromConf string"

instance FromConf (Maybe String) where
    fromConf (CV_String "") = Nothing
    fromConf (CV_String s) = Just s
    fromConf _ = error "fromConf string"

instance FromConf [String] where
    fromConf (CV_String s) = splitOn "," s
    fromConf _ = error "fromConf string"

instance FromConf Log.Level where
    fromConf (CV_String s) = logLevel s
    fromConf _ = error "fromConf log level"

----------------------------------------------------------------

logLevel :: String -> Log.Level
logLevel s = case lvs of
    lv : _ -> lv
    [] -> error $ "fromConf unknwon log-level " ++ s
  where
    lvs = [lv | (lv, "") <- reads u]
    u = map toUpper s

----------------------------------------------------------------

readConfig :: FilePath -> IO [Conf]
readConfig = parseFile config

----------------------------------------------------------------

config :: Parser [Conf]
config = commentLines *> many cfield <* eof
  where
    cfield = field <* commentLines

field :: Parser Conf
field = do
    k <- key
    sep
    v <- value
    if v == CV_String ""
        then fail ("\"" ++ k ++ ":\" does not specify a value")
        else return (k, v)

key :: Parser String
key = many1 (oneOf $ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ ['0' .. '9'] ++ "_-") <* spcs

sep :: Parser ()
sep = () <$ char ':' *> spcs

value :: Parser ConfValue
value = choice [try cv_int, try cv_bool, cv_string]

-- Trailing should be included in try to allow IP addresses.
cv_int :: Parser ConfValue
cv_int = CV_Int . read <$> many1 digit <* trailing

cv_bool :: Parser ConfValue
cv_bool =
    CV_Bool True <$ string "yes" <* trailing
        <|> CV_Bool False <$ string "no" <* trailing

cv_string :: Parser ConfValue
cv_string = CV_String <$> many (noneOf " \t\n") <* trailing
