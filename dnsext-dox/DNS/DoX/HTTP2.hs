{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP2 (
    http2PersistentResolver,
    http2Resolver,
    http2cPersistentResolver,
    http2cResolver,
    doHTTP,
    doHTTPOneshot,
    withTimeout,
)
where

import DNS.Do53.Client
import DNS.Do53.Internal
import qualified DNS.Log as Log
import DNS.Types
import DNS.Types.Decode
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Short (fromShort)
import qualified Data.ByteString.Short as Short
import Network.HTTP.Types
import Network.HTTP2.Client (Client, SendRequest, getResponseBodyChunk, requestBuilder, responseStatus)
import qualified Network.HTTP2.TLS.Client as H2
import System.Timeout (timeout)
import qualified UnliftIO.Exception as E

import DNS.DoX.Imports
import DNS.DoX.TLS

withTimeout :: ResolveInfo -> IO (Either DNSError Reply) -> IO (Either DNSError Reply)
withTimeout ResolveInfo{..} action = do
    mres <- timeout (ractionTimeoutTime rinfoActions) action
    case mres of
        Nothing -> return $ Left TimeoutExpired
        Just res -> return res

http2PersistentResolver :: PersistentResolver
http2PersistentResolver ri@ResolveInfo{..} body = do
    let proto = "H2"
    ident <- ractionGenId rinfoActions
    H2.run settings (show rinfoIP) rinfoPort $
        doHTTP proto ident ri body
  where
    settings = makeSettings ri

http2Resolver :: OneshotResolver
http2Resolver ri@ResolveInfo{..} q qctl = do
    let proto = "H2"
    ident <- ractionGenId rinfoActions
    withTimeout ri $
        H2.run settings (show rinfoIP) rinfoPort $
            doHTTPOneshot proto ident ri q qctl
  where
    settings = makeSettings ri

http2cPersistentResolver :: PersistentResolver
http2cPersistentResolver ri@ResolveInfo{..} body = do
    let proto = "H2C"
    ident <- ractionGenId rinfoActions
    H2.runH2C H2.defaultSettings (show rinfoIP) rinfoPort $
        doHTTP proto ident ri body

http2cResolver :: OneshotResolver
http2cResolver ri@ResolveInfo{..} q qctl = do
    let proto = "H2C"
    ident <- ractionGenId rinfoActions
    withTimeout ri $
        H2.runH2C H2.defaultSettings (show rinfoIP) rinfoPort $
            doHTTPOneshot proto ident ri q qctl

resolv
    :: String
    -> Word16
    -> ResolveInfo
    -> SendRequest
    -> Resolver
resolv proto ident ri@ResolveInfo{..} sendRequest q qctl =
    sendRequest req $ \rsp -> do
        when (responseStatus rsp /= Just ok200) $ E.throwIO OperationRefused
        let recvHTTP = recvManyN $ getResponseBodyChunk rsp
        (rx, bss) <- recvHTTP $ unVCLimit rinfoVCLimit
        now <- getTime
        case decodeChunks now bss of
            Left e -> E.throwIO e
            Right msg -> case checkRespM q ident msg of -- fixme
                Nothing -> return $ Right $ Reply name msg tx rx
                Just err -> return $ Left err
  where
    name = nameTag ri proto
    getTime = ractionGetTime rinfoActions
    wire = encodeQuery ident q qctl
    tx = BS.length wire
    hdr = clientDoHHeaders tx
    path = case rinfoPath of
        Nothing -> "/dns-query"
        Just p -> fromShort $ Short.takeWhile (/= 0x7b) p -- '{'
    req = requestBuilder methodPost path hdr $ BB.byteString wire

doHTTP
    :: String
    -> Word16
    -> ResolveInfo
    -> (Resolver -> IO a)
    -> Client a
doHTTP proto ident ri body sendRequest _aux =
    body $ resolv proto ident ri sendRequest

doHTTPOneshot
    :: String
    -> Identifier
    -> ResolveInfo
    -> Question
    -> QueryControls
    -> Client (Either DNSError Reply)
doHTTPOneshot proto ident ri@ResolveInfo{..} q qctl sendRequest _aux = do
    ractionLog rinfoActions Log.DEMO Nothing [qtag]
    resolv proto ident ri sendRequest q qctl
  where
    ~name = nameTag ri proto
    ~qtag = queryTag q name

clientDoHHeaders :: Int -> RequestHeaders
clientDoHHeaders len =
    [ (hUserAgent, "HaskellQuic/0.0.0")
    , (hContentType, "application/dns-message")
    , (hAccept, "application/dns-message")
    , (hContentLength, C8.pack $ show len)
    ]
