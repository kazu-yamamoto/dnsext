{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.HTTP2 where

-- GHC packages
import Data.ByteString.Char8 ()
import Data.ByteString.Builder (byteString)

-- dnsext-* packages
import DNS.Do53.Internal

-- other packages

import qualified UnliftIO.Exception as E
import Network.Run.TCP
import Network.Socket (
    HostName,
    PortNumber,
 )
import Network.HTTP2.Server
import qualified Network.HTTP.Types as HT

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
    let http2server = runTCPServer (Just host) (show port) $ runHTTP2Server cntinc
    return ([http2server], [readCounters cntget])
  where
    runHTTP2Server cntinc s = E.bracket (allocSimpleConfig s 4096)
                                 freeSimpleConfig
                                 (\config -> run config $ doHTTP env cntinc)

doHTTP
    :: Env
    -> CntInc
    -> Request
    -> Aux
    -> (Response -> [PushPromise] -> IO ())
    -> IO ()
doHTTP env cntinc req _aux sendResponse = do
        (_rx, rqs) <- recvManyN (getRequestBodyChunk req) 2048
        let send res = do
                let response = responseBuilder HT.ok200 header $ byteString res
                sendResponse response []
        cacheWorkerLogic env cntinc send rqs
      where
        header = [(HT.hContentType, "application/dns-message")]
