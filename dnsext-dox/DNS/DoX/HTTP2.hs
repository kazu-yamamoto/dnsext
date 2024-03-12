{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP2 (
    withHttp2Resolver,
    http2Resolver,
    withHttp2cResolver,
    http2cResolver,
    doHTTP,
    doHTTPOneshot,
    withTimeout,
)
where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Imports
import qualified DNS.Log as Log
import DNS.Types
import DNS.Types.Decode
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (fromShort)
import Network.HTTP.Types
import Network.HTTP2.Client (Client, Request, Response, getResponseBodyChunk, requestBuilder)
import qualified Network.HTTP2.TLS.Client as H2
import System.Timeout (timeout)
import qualified UnliftIO.Exception as E

withTimeout :: ResolveInfo -> IO (Either DNSError Result) -> IO (Either DNSError Result)
withTimeout ResolveInfo{..} action = do
    mres <- timeout (ractionTimeoutTime rinfoActions) action
    case mres of
        Nothing -> return $ Left TimeoutExpired
        Just res -> return res

withHttp2Resolver :: ShortByteString -> PipelineResolver
withHttp2Resolver path ri@ResolveInfo{..} body = do
    let proto = "H2"
    ident <- ractionGenId rinfoActions
    H2.run settings (show rinfoIP) rinfoPort $
        doHTTP proto ident path ri body
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
            }

http2Resolver :: ShortByteString -> OneshotResolver
http2Resolver path ri@ResolveInfo{..} q qctl = do
    let proto = "H2"
    ident <- ractionGenId rinfoActions
    withTimeout ri $
        H2.run settings (show rinfoIP) rinfoPort $
            doHTTPOneshot proto ident path ri q qctl
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
            }

withHttp2cResolver :: ShortByteString -> PipelineResolver
withHttp2cResolver path ri@ResolveInfo{..} body = do
    let proto = "H2C"
    ident <- ractionGenId rinfoActions
    H2.runH2C H2.defaultSettings (show rinfoIP) rinfoPort $
        doHTTP proto ident path ri body

http2cResolver :: ShortByteString -> OneshotResolver
http2cResolver path ri@ResolveInfo{..} q qctl = do
    let proto = "H2C"
    ident <- ractionGenId rinfoActions
    withTimeout ri $
        H2.runH2C H2.defaultSettings (show rinfoIP) rinfoPort $
            doHTTPOneshot proto ident path ri q qctl

resolv
    :: String
    -> ShortByteString
    -> Word16
    -> ResolveInfo
    -> (Request -> (Response -> IO (Either DNSError Result)) -> IO (Either DNSError Result))
    -> Resolver
resolv proto path ident ri@ResolveInfo{..} sendRequest q qctl =
    sendRequest req $ \rsp -> do
        let recvHTTP = recvManyN $ getResponseBodyChunk rsp
        (rx, bss) <- recvHTTP $ unVCLimit rinfoVCLimit
        now <- getTime
        case decodeChunks now bss of
            Left e -> E.throwIO e
            Right msg -> case checkRespM q ident msg of -- fixme
                Nothing -> return $ Right $ toResult ri proto $ Reply msg tx rx
                Just err -> return $ Left err
  where
    getTime = ractionGetTime rinfoActions
    wire = encodeQuery ident q qctl
    tx = BS.length wire
    hdr = clientDoHHeaders tx
    req = requestBuilder methodPost (fromShort path) hdr $ BB.byteString wire

doHTTP
    :: String
    -> Word16
    -> ShortByteString
    -> ResolveInfo
    -> (Resolver -> IO a)
    -> Client a
doHTTP proto ident path ri body sendRequest _aux =
    body $ resolv proto path ident ri sendRequest

doHTTPOneshot
    :: String
    -> Identifier
    -> ShortByteString
    -> ResolveInfo
    -> Question
    -> QueryControls
    -> Client (Either DNSError Result)
doHTTPOneshot proto ident path ri@ResolveInfo{..} q qctl sendRequest _aux = do
    ractionLog rinfoActions Log.DEMO Nothing [tag]
    resolv proto path ident ri sendRequest q qctl
  where
    ~tag = lazyTag ri q proto

clientDoHHeaders :: Int -> RequestHeaders
clientDoHHeaders len =
    [ (hUserAgent, "HaskellQuic/0.0.0")
    , (hContentType, "application/dns-message")
    , (hAccept, "application/dns-message")
    , (hContentLength, C8.pack $ show len)
    ]
