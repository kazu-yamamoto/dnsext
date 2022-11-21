{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.HTTP2 where

import DNS.Types.Decode
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Char8 as C8
import Foreign.Marshal.Alloc (mallocBytes, free)
import Network.HTTP.Types
import qualified Network.HTTP2.Client as H2
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
    E.bracket (allocConfig ctx 4096) freeConfig $ \conf -> H2.run cliconf conf cli
  where
    req = H2.requestBuilder methodPost "/dns-query" clientDoHHeaders $ BB.byteString msg
    cliconf = H2.ClientConfig {
        H2.scheme = "https"
      , H2.authority = C8.pack hostname
      , H2.cacheLimit = 20
      }
    cli sendRequest = sendRequest req $ \rsp -> do
        bs <- loop rsp ""
        print $ decode bs
      where
        loop rsp bs0 = do
            bs <- H2.getResponseBodyChunk rsp
            if bs == "" then return bs0
                        else loop rsp (bs0 <> bs)

allocConfig :: Context -> Int -> IO H2.Config
allocConfig ctx bufsiz = do
    buf <- mallocBytes bufsiz
    timmgr <- T.initialize $ 30 * 1000000
    (recv, recvBuf) <- makeRecv $ recvTLS ctx
    recvN <- makeReceiveN "" recv recvBuf
    let config = H2.Config {
            H2.confWriteBuffer = buf
          , H2.confBufferSize = bufsiz
          , H2.confSendAll = sendTLS ctx
          , H2.confReadN = recvN
          , H2.confPositionReadMaker = H2.defaultPositionReadMaker
          , H2.confTimeoutManager = timmgr
          }
    return config

-- | Deallocating the resource of the simple configuration.
freeConfig :: H2.Config -> IO ()
freeConfig conf = do
    free $ H2.confWriteBuffer conf
    T.killManager $ H2.confTimeoutManager conf
