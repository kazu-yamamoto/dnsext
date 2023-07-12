{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.HTTP3 where

-- GHC packages

import Data.ByteString (ByteString)
import Data.ByteString.Char8 ()

-- dnsext-* packages

-- other packages

import Network.QUIC.Server (ServerConfig(..))
import qualified Network.QUIC.Server as QUIC
import qualified Network.HTTP3.Server as H3
import Network.TLS (Credentials (..))
import qualified System.TimeManager as T

-- this package
import DNS.Cache.Server.HTTP2
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.Types

----------------------------------------------------------------
data Http3ServerConfig = Http3ServerConfig
    { http3_idle_timeout :: Int
    }

http3Server :: Credentials -> Http3ServerConfig -> Server
http3Server creds Http3ServerConfig{..} env port host = do
    (cntget, cntinc) <- newCounters
    let http3server = T.withManager (http3_idle_timeout * 1000000) $ \mgr ->
          QUIC.run sconf $ \conn ->
              H3.run conn (conf mgr) $ doHTTP env cntinc
    return ([http3server], [readCounters cntget])
  where
    sconf = getServerConfig creds host port "h3"
    conf mgr =
        H3.Config
            { confHooks = H3.defaultHooks
            , confTimeoutManager = mgr
            , confPositionReadMaker = H3.defaultPositionReadMaker
            }

getServerConfig :: Credentials -> String -> PortNumber -> ByteString -> ServerConfig
getServerConfig creds host port alpn =
    QUIC.defaultServerConfig
        { scAddresses = [(read host, port)]
        , scALPN = Just (\_ bss -> if alpn `elem` bss then return alpn else return "")
        , scCredentials = creds
        }
