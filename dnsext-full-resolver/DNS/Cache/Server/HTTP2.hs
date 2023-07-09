{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.HTTP2 where

-- GHC packages

import Data.ByteString.Builder (byteString)
import Data.ByteString.Char8 ()

-- dnsext-* packages
import DNS.Do53.Internal

-- other packages

import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import qualified Network.HTTP2.TLS.Server as H2

-- this package
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.Types

----------------------------------------------------------------
data Http2cServerConfig = Http2cServerConfig
    { http2c_idle_timeout :: Int
    }

http2cServer :: Http2cServerConfig -> Server
http2cServer _http2conf env port host = do
    (cntget, cntinc) <- newCounters
    let http2server = H2.runH2C host port $ doHTTP env cntinc
    return ([http2server], [readCounters cntget])

doHTTP
    :: Env
    -> CntInc
    -> H2.Server
doHTTP env cntinc req _aux sendResponse = do
    (_rx, rqs) <- recvManyN (H2.getRequestBodyChunk req) 2048
    let send res = do
            let response = H2.responseBuilder HT.ok200 header $ byteString res
            sendResponse response []
    cacheWorkerLogic env cntinc send rqs
  where
    header = [(HT.hContentType, "application/dns-message")]
