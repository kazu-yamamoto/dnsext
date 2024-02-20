{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RecordWildCards #-}

module Config (
    Config (..),
    defaultConfig,
    parseConfig,
    showConfig,
) where

import Control.Monad (void)
import Control.Monad.Trans.State (StateT (..), evalStateT)
import qualified DNS.Log as Log
import Data.Char (toUpper)
import Data.List
import Data.List.Split (splitOn)
import Data.String (fromString)
import Text.Parsec
import Text.Parsec.ByteString.Lazy

import DNS.Iterative.Internal (LocalZoneType (..))
import DNS.Types (Domain, ResourceRecord (..), isSubDomainOf)
import DNS.ZoneFile (Context (cx_name, cx_zone), defaultContext, parseLineRR)

import Parser

data Config = Config
    { cnf_log :: Bool
    , cnf_log_output :: Log.Output
    , cnf_log_level :: Log.Level
    , cnf_cert_file :: FilePath
    , cnf_key_file :: FilePath
    , cnf_trust_anchor_file :: Maybe FilePath
    , cnf_root_hints :: Maybe FilePath
    , cnf_cache_size :: Int
    , cnf_disable_v6_ns :: Bool
    , cnf_local_zones :: [(Domain, LocalZoneType, [ResourceRecord])]
    , cnf_dns_addrs :: [String]
    , cnf_resolve_timeout :: Int
    , cnf_cachers :: Int
    , cnf_workers :: Int
    , cnf_udp :: Bool
    , cnf_udp_port :: Int
    , cnf_vc_query_max_size :: Int
    , cnf_vc_idle_timeout :: Int
    , cnf_vc_slowloris_size :: Int
    , cnf_tcp :: Bool
    , cnf_tcp_port :: Int
    , cnf_tls :: Bool
    , cnf_tls_port :: Int
    , cnf_tls_session_ticket_lifetime :: Int
    , cnf_quic :: Bool
    , cnf_quic_port :: Int
    , cnf_h2c :: Bool
    , cnf_h2c_port :: Int
    , cnf_h2 :: Bool
    , cnf_h2_port :: Int
    , cnf_h3 :: Bool
    , cnf_h3_port :: Int
    , cnf_monitor_port :: Int
    , cnf_monitor_addrs :: [String]
    , cnf_monitor_stdio :: Bool
    , cnf_threads_dumper :: Bool
    , cnf_dnstap :: Bool
    , cnf_dnstap_socket_path :: FilePath
    , cnf_dnstap_reconnect_interval :: Int
    , cnf_webapi :: Bool
    , cnf_webapi_addr :: String
    , cnf_webapi_port :: Int
    }
    deriving (Show)

defaultConfig :: Config
defaultConfig =
    Config
        { cnf_log = True
        , cnf_log_output = Log.Stdout
        , cnf_log_level = Log.WARN
        , cnf_cert_file = "fullchain.pem"
        , cnf_key_file = "privkey.pem"
        , cnf_trust_anchor_file = Nothing
        , cnf_root_hints = Nothing
        , cnf_cache_size = 2 * 1024
        , cnf_disable_v6_ns = False
        , cnf_local_zones = []
        , cnf_dns_addrs = ["127.0.0.1", "::1"]
        , cnf_resolve_timeout = 10000000
        , cnf_cachers = 4
        , cnf_workers = 128
        , cnf_udp = True
        , cnf_udp_port = 53
        , cnf_vc_query_max_size = 2048
        , cnf_vc_idle_timeout = 30
        , cnf_vc_slowloris_size = 50
        , cnf_tcp = True
        , cnf_tcp_port = 53
        , cnf_tls = True
        , cnf_tls_port = 853
        , cnf_tls_session_ticket_lifetime = 7200
        , cnf_quic = True
        , cnf_quic_port = 853
        , cnf_h2c = True
        , cnf_h2c_port = 80
        , cnf_h2 = True
        , cnf_h2_port = 443
        , cnf_h3 = True
        , cnf_h3_port = 443
        , cnf_monitor_port = 10023
        , cnf_monitor_addrs = []
        , cnf_monitor_stdio = False
        , cnf_threads_dumper = False
        , cnf_dnstap = True
        , cnf_dnstap_socket_path = "/tmp/bowline.sock"
        , cnf_dnstap_reconnect_interval = 10
        , cnf_webapi = True
        , cnf_webapi_addr = "127.0.0.1"
        , cnf_webapi_port = 8080
        }

----------------------------------------------------------------

showConfig :: Config -> [String]
showConfig conf = showConfig1 conf ++ showConfig2 conf

{- FOURMOLU_DISABLE -}
showConfig1 :: Config -> [String]
showConfig1 Config{..} =
    [ showAddrPort "Mointor" True     cnf_monitor_addrs cnf_monitor_port
    , showAddrPort "UDP"     cnf_udp  cnf_dns_addrs     cnf_udp_port
    , showAddrPort "TCP"     cnf_tcp  cnf_dns_addrs     cnf_tcp_port
    , showAddrPort "TLS"     cnf_tls  cnf_dns_addrs     cnf_tls_port
    , showAddrPort "QUIC"    cnf_quic cnf_dns_addrs     cnf_quic_port
    , showAddrPort "H2C"     cnf_h2c  cnf_dns_addrs     cnf_h2c_port
    , showAddrPort "H2"      cnf_h2   cnf_dns_addrs     cnf_h2_port
    , showAddrPort "H3"      cnf_h3   cnf_dns_addrs     cnf_h3_port
    ]
  where
    showAddrPort tag enable addrs port
        | enable = tag ++ ": " ++ intercalate ", " (map (addrport port) addrs)
        | otherwise = tag ++ ": disabled"
    addrport port a
        | ':' `elem` a = "[" ++ a ++ "]:" ++ show port
        | otherwise = a ++ ":" ++ show port
{- FOURMOLU_ENABLE -}

showConfig2 :: Config -> [String]
showConfig2 conf =
    [ -- field "capabilities" numCapabilities
      field'_ "log output" (showOut . cnf_log_output)
    , field' "log level" cnf_log_level
    , field' "max cache size" cnf_cache_size
    , field' "disable queries to IPv6 NS" cnf_disable_v6_ns
    , field' "cachers" cnf_cachers
    , field' "workers" cnf_workers
    ]
  where
    field' label' get = field'_ label' (show . get)
    field'_ label' toS = label' ++ ": " ++ toS conf
    showOut Log.Stdout = "stdout"
    showOut Log.Stderr = "stderr"

----------------------------------------------------------------

-- | Parsing a configuration file to get an 'Config'.
parseConfig :: FilePath -> IO Config
parseConfig file = makeConfig defaultConfig <$> readConfig file

makeConfig :: Config -> [Conf] -> Config
makeConfig def conf =
    Config
        { cnf_log = get "log" cnf_log
        , cnf_log_output = Log.Stdout -- fixme
        , cnf_log_level = get "log-level" cnf_log_level
        , cnf_cert_file = get "cert-file" cnf_cert_file
        , cnf_key_file = get "key-file" cnf_key_file
        , cnf_trust_anchor_file = get "trust-anchor-file" cnf_trust_anchor_file
        , cnf_root_hints = get "root-hints" cnf_root_hints
        , cnf_cache_size = get "cache-size" cnf_cache_size
        , cnf_disable_v6_ns = get "disable-v6-ns" cnf_disable_v6_ns
        , cnf_local_zones = localZones
        , cnf_dns_addrs = get "dns-addrs" cnf_dns_addrs
        , cnf_resolve_timeout = get "resolve-timeout" cnf_resolve_timeout
        , cnf_cachers = get "cachers" cnf_cachers
        , cnf_workers = get "workers" cnf_workers
        , cnf_udp = get "udp" cnf_udp
        , cnf_udp_port = get "udp-port" cnf_udp_port
        , cnf_vc_query_max_size = get "vc-query-max-size" cnf_vc_query_max_size
        , cnf_vc_idle_timeout = get "vc-idle-timeout" cnf_vc_idle_timeout
        , cnf_vc_slowloris_size = get "vc-slowloris-size" cnf_vc_slowloris_size
        , cnf_tcp = get "tcp" cnf_tcp
        , cnf_tcp_port = get "tcp-port" cnf_tcp_port
        , cnf_tls = get "tls" cnf_tls
        , cnf_tls_port = get "tls-port" cnf_tls_port
        , cnf_tls_session_ticket_lifetime = get "tls-session-ticket-lifetime" cnf_tls_session_ticket_lifetime
        , cnf_quic = get "quic" cnf_quic
        , cnf_quic_port = get "quic-port" cnf_quic_port
        , cnf_h2c = get "h2c" cnf_h2c
        , cnf_h2c_port = get "h2c-port" cnf_h2c_port
        , cnf_h2 = get "h2" cnf_h2
        , cnf_h2_port = get "h2-port" cnf_h2_port
        , cnf_h3 = get "h3" cnf_h3
        , cnf_h3_port = get "h3-port" cnf_h3_port
        , cnf_monitor_port = get "monitor-port" cnf_monitor_port
        , cnf_monitor_addrs = get "monitor-addrs" cnf_monitor_addrs
        , cnf_monitor_stdio = get "monitor-stdio" cnf_monitor_stdio
        , cnf_threads_dumper = get "threads-dumper" cnf_threads_dumper
        , cnf_dnstap = get "dnstap" cnf_dnstap
        , cnf_dnstap_socket_path = get "dnstap-socket-patch" cnf_dnstap_socket_path
        , cnf_dnstap_reconnect_interval = get "dnstap-reconnect-interval" cnf_dnstap_reconnect_interval
        , cnf_webapi = get "webapi" cnf_webapi
        , cnf_webapi_addr = get "webapi-addr" cnf_webapi_addr
        , cnf_webapi_port = get "webapi-port" cnf_webapi_port
        }
  where
    get k func = maybe (func def) fromConf $ lookup k conf
    --
    localZones = case mapM parseLocalZone $ unfoldr getLocalZone conf of
        Right zones -> zones
        Left es -> error $ "parse error during local-data: " ++ es
    parseLocalZone (d, zt, xs) = evalStateT ((,,) d zt . subdoms d <$> mapM getRR xs) defaultContext{cx_zone = d, cx_name = d}
    subdoms d rrs = [rr | rr <- rrs, rrname rr `isSubDomainOf` d]
    getRR s = StateT $ parseLineRR $ fromString s

-- $setup
-- >>> :seti -XOverloadedStrings

{- FOURMOLU_DISABLE -}
-- |
-- >>> getLocalZone [("foo",CV_Int 4),("local-zone",CV_Strings ["example.", "static"]),("local-data",CV_String "a.example. A 203.0.113.5"),("bar",CV_Bool True)]
-- Just (("example.",LZ_Static,["a.example. A 203.0.113.5"]),[("bar",CV_Bool True)])
getLocalZone :: [Conf] -> Maybe ((Domain, LocalZoneType, [String]), [Conf])
getLocalZone [] = Nothing
getLocalZone ((k, v):xs)
    | k == "local-zone" =
        let cstrs = fromConf v
            ~err = error $ "unknown local-zone pattern: " ++ show cstrs
            (zone, zt) = maybe err id $ getLocalZone' cstrs
            (ds, ys) = getLocalData id xs
        in  Just ((zone, zt, ds), ys)
    | otherwise = getLocalZone xs
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- |
-- >>> getLocalZone' ["example.", "static"]
-- Just ("example.",LZ_Static)
-- >>> getLocalZone' ["example.", "redirect"]
-- Just ("example.",LZ_Redirect)
getLocalZone' :: [String] -> Maybe (Domain, LocalZoneType)
getLocalZone' [s1,s2] = (,) (fromString s1) <$> zoneType s2
  where
    zoneType s = case s of
        "deny"      -> Just LZ_Deny
        "refuse"    -> Just LZ_Refuse
        "static"    -> Just LZ_Static
        "redirect"  -> Just LZ_Redirect
        _           -> Nothing
getLocalZone' _       = Nothing
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
getLocalData :: ([String] -> [String]) -> [Conf] -> ([String], [Conf])
getLocalData a []        = (a [], [])
getLocalData a xxs@((k, v):xs)
    | k == "local-data"  = getLocalData (a . (fromConf v :)) xs
    | otherwise          = (a [], xxs)
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

type Conf = (String, ConfValue)

data ConfValue = CV_Int Int | CV_Bool Bool | CV_String String | CV_Strings [String] deriving (Eq, Show)

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
    fromConf _ = error "fromConf maybe string"

instance FromConf [String] where
    fromConf (CV_String s) = filter (/= "") $ splitOn "," s
    fromConf (CV_Strings ss) = ss
    fromConf _ = error "fromConf string list"

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

{- FOURMOLU_DISABLE -}
getInclude :: [Conf] -> Maybe (FilePath, [Conf])
getInclude []         = Nothing
getInclude ((k, v):xs)
    | k == "include"  = Just (fromConf v, xs)
    | otherwise       = getInclude xs
{- FOURMOLU_ENABLE -}

includesConfs :: [Conf] -> IO [Conf]
includesConfs cs = concat <$> mapM loadInclude (getIncludes cs)
  where
    getIncludes = unfoldr getInclude
    loadInclude path = do
        putStrLn $ "loading included conf: " ++ path
        parseFile config path

{- FOURMOLU_DISABLE -}
nestedLimit :: Int
nestedLimit = 5

nestedConfs :: Int -> [Conf] -> IO [Conf]
nestedConfs n cs0 =  do
    cs1 <- includesConfs cs0
    let result
            | null cs1   = pure cs0
            | n <= 0     = error $ "nestedConfs: nested-limit is " ++ show nestedLimit ++ ", limit exceeded."
            | otherwise  = (cs0 ++) <$> nestedConfs (n-1) cs1
    result
{- FOURMOLU_ENABLE -}

readConfig :: FilePath -> IO [Conf]
readConfig path = parseFile config path >>= nestedConfs nestedLimit

----------------------------------------------------------------

config :: Parser [Conf]
config = commentLines *> many cfield <* eof
  where
    cfield = field <* commentLines

field :: Parser Conf
field = (,) <$> key <*> (sep *> value)

key :: Parser String
key = many1 (oneOf $ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ ['0' .. '9'] ++ "_-") <* spcs

sep :: Parser ()
sep = void $ char ':' *> spcs

dquote :: Parser ()
dquote = void $ char '"'

value :: Parser ConfValue
value = choice [try cv_int, try cv_bool, cv_strings]

-- Trailing should be included in try to allow IP addresses.
cv_int :: Parser ConfValue
cv_int = CV_Int . read <$> many1 digit <* trailing

cv_bool :: Parser ConfValue
cv_bool =
    CV_Bool True <$ string "yes" <* trailing
        <|> CV_Bool False <$ string "no" <* trailing

{- FOURMOLU_DISABLE -}
cv_string' :: Parser String
cv_string' =
    dquote *> (many (noneOf "\"\n")) <* dquote  <|>
    many1 (noneOf "\"# \t\n")
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
-- |
-- >>> parse cv_strings "" "\"conf.txt\"\n"
-- Right (CV_String "conf.txt")
-- >>> parse cv_strings "" "\"conf.txt\" # foo\n"
-- Right (CV_String "conf.txt")
-- >>> parse cv_strings "" "\"example. 1800 TXT 'abc'\" static\n"
-- Right (CV_Strings ["example. 1800 TXT 'abc'","static"])
-- >>> parse cv_strings "" "\"example. 1800 TXT 'abc'\" static # foo\n"
-- Right (CV_Strings ["example. 1800 TXT 'abc'","static"])
cv_strings :: Parser ConfValue
cv_strings = do
    v1 <- cv_string'
    vs <- many (try (spcs1 *> cv_string')) <* trailing
    pure $ if null vs
           then CV_String v1
           else CV_Strings $ v1:vs
{- FOURMOLU_ENABLE -}
