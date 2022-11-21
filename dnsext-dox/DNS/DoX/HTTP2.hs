{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.HTTP2 where

import DNS.Types.Decode
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Char8 as C8
import Foreign.Marshal.Alloc (mallocBytes, free)
import Network.HTTP.Types
import Network.HTTP2.Client
import Network.Socket hiding (recvBuf)
import Network.Socket.BufferPool
import Network.TLS hiding (HostName)
import qualified System.TimeManager as T
import qualified UnliftIO.Exception as E

import DNS.DoX.Common

doh :: HostName -> PortNumber -> WireFormat -> IO ()
doh hostname port qry = do
    E.bracket open close $ \sock ->
      E.bracket (contextNew sock params) bye $ \ctx -> do
        handshake ctx
        client ctx hostname qry
  where
    params = getTLSParams hostname "h2" False
    open = do
        ai <- makeAddrInfo (Just hostname) port
        sock <- openSocket ai

        let sockaddr = addrAddress ai
        connect sock sockaddr
        return sock

client :: Context -> HostName -> ByteString -> IO ()
client ctx hostname msg =
    E.bracket (allocConfig ctx 4096) freeConfig $ \conf -> run cliconf conf cli
  where
    req = requestBuilder methodPost "/dns-query" clientDoHHeaders $ BB.byteString msg
    cliconf = ClientConfig {
        scheme = "https"
      , authority = C8.pack hostname
      , cacheLimit = 20
      }
    cli sendRequest = sendRequest req $ \rsp -> do
        bs <- loop rsp ""
        print $ decode bs
      where
        loop rsp bs0 = do
            bs <- getResponseBodyChunk rsp
            if bs == "" then return bs0
                        else loop rsp (bs0 <> bs)

allocConfig :: Context -> Int -> IO Config
allocConfig ctx bufsiz = do
    buf <- mallocBytes bufsiz
    timmgr <- T.initialize $ 30 * 1000000
    (recv, recvBuf) <- makeRecv $ recvTLS ctx
    recvN <- makeReceiveN "" recv recvBuf
    let config = Config {
            confWriteBuffer = buf
          , confBufferSize = bufsiz
          , confSendAll = sendTLS ctx
          , confReadN = recvN
          , confPositionReadMaker = defaultPositionReadMaker
          , confTimeoutManager = timmgr
          }
    return config

-- | Deallocating the resource of the simple configuration.
freeConfig :: Config -> IO ()
freeConfig conf = do
    free $ confWriteBuffer conf
    T.killManager $ confTimeoutManager conf
