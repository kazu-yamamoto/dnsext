{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP2 (
    http2Resolver,
    doHTTP,
)
where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Common
import DNS.DoX.Imports
import DNS.Types
import DNS.Types.Decode
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (fromShort)
import Foreign.Marshal.Alloc (free, mallocBytes)
import Network.HTTP.Types
import Network.HTTP2.Client
import Network.Socket hiding (recvBuf)
import Network.Socket.BufferPool
import Network.TLS hiding (HostName)
import qualified System.TimeManager as T
import qualified UnliftIO.Exception as E
import qualified DNS.Log as Log

http2Resolver :: ShortByteString -> VCLimit -> Resolver
http2Resolver path lim ri@ResolvInfo{..} q qctl = E.bracket open close $ \sock ->
    E.bracket (contextNew sock params) bye $ \ctx -> do
        handshake ctx
        ident <- ractionGenId rinfoActions
        h2resolver ctx ident path lim ri q qctl
  where
    open = do
        s <- openTCP rinfoHostName rinfoPortNumber
        winhack s
        return s
    params = getTLSParams rinfoHostName "h2" False

winhack :: Socket -> IO ()
#ifdef mingw32_HOST_OS
winhack s = setSocketOption s RecvTimeOut 3000000
#else
winhack _ = return ()
#endif

h2resolver :: Context -> Identifier -> ShortByteString -> VCLimit -> Resolver
h2resolver ctx ident path lim ri@ResolvInfo{..} q qctl =
    E.bracket (allocConfig ctx 4096) freeConfig $ \conf ->
        run cliconf conf $ doHTTP "HTTP/2" ident path lim ri q qctl
  where
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = C8.pack rinfoHostName
            , cacheLimit = 20
            }

doHTTP
    :: String
    -> Identifier
    -> ShortByteString
    -> VCLimit
    -> ResolvInfo
    -> Question
    -> QueryControls
    -> Client Result
doHTTP proto ident path lim ri@ResolvInfo{..} q@Question{..} qctl sendRequest = do
    ractionLog rinfoActions Log.DEMO Nothing [tag]
    sendRequest req $ \rsp -> do
        let recvHTTP = recvManyN $ getResponseBodyChunk rsp
        (rx, bss) <- recvHTTP $ unVCLimit lim
        now <- getTime
        case decodeChunks now bss of
            Left e -> E.throwIO e
            Right (msg, _) -> case checkRespM q ident msg of -- fixme
                Nothing -> do
                    ractionLog rinfoActions Log.DEMO Nothing [tag ++ ": win"]
                    return $ toResult ri proto $ Reply msg tx rx
                Just err -> E.throwIO err
  where
    ~tag = "query " ++ show qname ++ " " ++ show qtype ++ " to "++ rinfoHostName ++ "#" ++ show rinfoPortNumber ++ "/" ++ proto
    getTime = ractionGetTime rinfoActions
    wire = encodeQuery ident q qctl
    tx = BS.length wire
    hdr = clientDoHHeaders wire
    req = requestBuilder methodPost (fromShort path) hdr $ BB.byteString wire

allocConfig :: Context -> Int -> IO Config
allocConfig ctx bufsiz = do
    buf <- mallocBytes bufsiz
    timmgr <- T.initialize $ 30 * 1000000
    recvN <- makeRecvN "" $ recvTLS ctx
    let config =
            Config
                { confWriteBuffer = buf
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
