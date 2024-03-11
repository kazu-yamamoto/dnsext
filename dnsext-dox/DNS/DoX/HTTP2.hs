{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP2 (
    http2Resolver,
    http2cResolver,
    doHTTP,
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
import Network.HTTP2.Client (Client, getResponseBodyChunk, requestBuilder)
import qualified Network.HTTP2.TLS.Client as H2
import System.Timeout (timeout)
import qualified UnliftIO.Exception as E

withTimeout :: ResolveInfo -> String -> IO Reply -> IO (Either DNSError Result)
withTimeout ri@ResolveInfo{..} proto action = do
    mres <- timeout (ractionTimeoutTime rinfoActions) action
    case mres of
        Nothing -> return $ Left TimeoutExpired
        Just res -> return $ Right $ toResult ri proto res

http2Resolver :: ShortByteString -> OneshotResolver
http2Resolver path ri@ResolveInfo{..} q qctl = do
    let proto = "H2"
    ident <- ractionGenId rinfoActions
    withTimeout ri proto $
        H2.run settings (show rinfoIP) rinfoPort $
            doHTTP proto ident path ri q qctl
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
            }

http2cResolver :: ShortByteString -> OneshotResolver
http2cResolver path ri@ResolveInfo{..} q qctl = do
    let proto = "H2C"
    ident <- ractionGenId rinfoActions
    withTimeout ri proto $
        H2.runH2C H2.defaultSettings (show rinfoIP) rinfoPort $
            doHTTP proto ident path ri q qctl

doHTTP
    :: String
    -> Identifier
    -> ShortByteString
    -> ResolveInfo
    -> Question
    -> QueryControls
    -> Client Reply
doHTTP proto ident path ri@ResolveInfo{..} q qctl sendRequest _aux = do
    ractionLog rinfoActions Log.DEMO Nothing [tag]
    sendRequest req $ \rsp -> do
        let recvHTTP = recvManyN $ getResponseBodyChunk rsp
        (rx, bss) <- recvHTTP $ unVCLimit rinfoVCLimit
        now <- getTime
        case decodeChunks now bss of
            Left e -> E.throwIO e
            Right msg -> case checkRespM q ident msg of -- fixme
                Nothing -> return $ Reply msg tx rx
                Just err -> E.throwIO err
  where
    ~tag = lazyTag ri q proto
    getTime = ractionGetTime rinfoActions
    wire = encodeQuery ident q qctl
    tx = BS.length wire
    hdr = clientDoHHeaders tx
    req = requestBuilder methodPost (fromShort path) hdr $ BB.byteString wire

clientDoHHeaders :: Int -> RequestHeaders
clientDoHHeaders len =
    [ (hUserAgent, "HaskellQuic/0.0.0")
    , (hContentType, "application/dns-message")
    , (hAccept, "application/dns-message")
    , (hContentLength, C8.pack $ show len)
    ]
