{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP2 where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.Types
import DNS.Types.Decode
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

http2Resolver :: Resolver
http2Resolver ri@ResolvInfo{..} q qctl = E.bracket open close $ \sock ->
      E.bracket (contextNew sock params) bye $ \ctx -> do
        handshake ctx
        ident <- ractionGenId rinfoActions
        client ctx ident ri q qctl
  where
    open = openTCP rinfoHostName rinfoPortNumber
    params = getTLSParams rinfoHostName "h2" False


client :: Context -> Identifier -> Resolver
client ctx ident ResolvInfo{..} q qctl =
    E.bracket (allocConfig ctx 4096) freeConfig $ \conf -> run cliconf conf cli
  where
    wire = encodeQuery ident q qctl
    hdr = clientDoHHeaders wire
    req = requestBuilder methodPost "/dns-query" hdr $ BB.byteString wire
    cliconf = ClientConfig {
        scheme = "https"
      , authority = C8.pack rinfoHostName
      , cacheLimit = 20
      }
    cli sendRequest = sendRequest req $ \rsp -> do
        bs <- loop rsp ""
        now <- ractionGetTime rinfoActions
        case decodeAt now bs of
            Left  e   -> E.throwIO e
            Right msg -> case checkRespM q ident msg of
                Nothing  -> return msg
                Just err -> E.throwIO err
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
