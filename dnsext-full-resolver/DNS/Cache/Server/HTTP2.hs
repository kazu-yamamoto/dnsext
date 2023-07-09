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
import Network.HTTP2.Server
import Network.HTTP2.TLS.Server

-- this package
import DNS.Cache.Iterative (Env (..))
import DNS.Cache.Server.Pipeline

----------------------------------------------------------------
data Http2ServerConfig = Http2ServerConfig
    { http2_idle_timeout :: Int
    }

http2Server
    :: Http2ServerConfig
    -> Env
    -> PortNumber
    -> HostName
    -> IO ([IO ()], [IO Status])
http2Server _http2conf env port host = do
    (cntget, cntinc) <- newCounters
    let http2server = runH2C host port $ doHTTP env cntinc
    return ([http2server], [readCounters cntget])

doHTTP
    :: Env
    -> CntInc
    -> Server
doHTTP env cntinc req _aux sendResponse = do
    (_rx, rqs) <- recvManyN (getRequestBodyChunk req) 2048
    let send res = do
            let response = responseBuilder HT.ok200 header $ byteString res
            sendResponse response []
    cacheWorkerLogic env cntinc send rqs
  where
    header = [(HT.hContentType, "application/dns-message")]
