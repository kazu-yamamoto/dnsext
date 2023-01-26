{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP2 (
    http2Resolver
  , doHTTP
  ) where

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

http2Resolver :: VCLimit -> Resolver
http2Resolver lim ri@ResolvInfo{..} q qctl = E.bracket open close $ \sock ->
      E.bracket (contextNew sock params) bye $ \ctx -> do
        handshake ctx
        ident <- ractionGenId rinfoActions
        h2resolver ctx ident lim ri q qctl
  where
    open = openTCP rinfoHostName rinfoPortNumber
    params = getTLSParams rinfoHostName "h2" False

h2resolver :: Context -> Identifier -> VCLimit -> Resolver
h2resolver ctx ident lim ri@ResolvInfo{..} q qctl =
    E.bracket (allocConfig ctx 4096) freeConfig $ \conf ->
        run cliconf conf $ doHTTP lim ri q qctl ident
  where
    cliconf = ClientConfig {
        scheme = "https"
      , authority = C8.pack rinfoHostName
      , cacheLimit = 20
      }

doHTTP :: VCLimit -> ResolvInfo -> Question -> QueryControls -> Identifier -> Client DNSMessage
doHTTP lim ResolvInfo{..} q qctl ident sendRequest = sendRequest req $ \rsp -> do
    let recvHTTP = recvManyN $ getResponseBodyChunk rsp
    (_,bss) <- recvHTTP lim
    now <- getTime
    case decodeChunks now bss of
        Left  e       -> E.throwIO e
        Right (msg,_) -> case checkRespM q ident msg of -- fixme
            Nothing  -> return msg
            Just err -> E.throwIO err
  where
    getTime = ractionGetTime rinfoActions
    wire = encodeQuery ident q qctl
    hdr = clientDoHHeaders wire
    req = requestBuilder methodPost "/dns-query" hdr $ BB.byteString wire

allocConfig :: Context -> Int -> IO Config
allocConfig ctx bufsiz = do
    buf <- mallocBytes bufsiz
    timmgr <- T.initialize $ 30 * 1000000
    recvN <- makeRecvN "" $ recvTLS ctx
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
