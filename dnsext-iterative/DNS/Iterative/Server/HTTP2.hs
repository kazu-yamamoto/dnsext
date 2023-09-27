{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP2 where

-- GHC packages

import Data.ByteString.Builder (byteString)
import Data.ByteString.Char8 ()

-- dnsext-* packages
import DNS.Do53.Internal
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages

import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import qualified Network.HTTP2.TLS.Server as H2TLS
import Network.TLS (Credentials (..))

-- this package
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

----------------------------------------------------------------
http2Server :: Credentials -> VcServerConfig -> Server
http2Server creds VcServerConfig{..} env port host = do
    let http2server = H2TLS.run settings creds host port $ doHTTP env
    return [http2server]
  where
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
            }

newtype Http2cServerConfig = Http2cServerConfig
    { http2c_idle_timeout :: Int
    }

http2cServer :: VcServerConfig -> Server
http2cServer VcServerConfig{..} env port host = do
    let http2server = H2TLS.runH2C settings host port $ doHTTP env
    return [http2server]
  where
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
            }

doHTTP
    :: Env
    -> H2.Server
doHTTP env req aux sendResponse = do
    (_rx, rqs) <- recvManyN (H2.getRequestBodyChunk req) 2048
    let send res = do
            let response = H2.responseBuilder HT.ok200 header $ byteString res
            sendResponse response []
        mysa = H2.auxMySockAddr aux
        peersa = H2.auxPeerSockAddr aux
    cacheWorkerLogic env send DOH mysa peersa rqs
  where
    header = [(HT.hContentType, "application/dns-message")]
