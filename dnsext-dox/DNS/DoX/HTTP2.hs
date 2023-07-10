{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP2 (
    http2Resolver,
    http2cResolver,
    doHTTP,
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
import qualified UnliftIO.Exception as E

http2Resolver :: ShortByteString -> VCLimit -> Resolver
http2Resolver path lim ri@ResolvInfo{..} q qctl = do
    ident <- ractionGenId rinfoActions
    H2.run H2.defaultSettings rinfoHostName rinfoPortNumber $
        doHTTP "H2" ident path lim ri q qctl

http2cResolver :: ShortByteString -> VCLimit -> Resolver
http2cResolver path lim ri@ResolvInfo{..} q qctl = do
    ident <- ractionGenId rinfoActions
    H2.runH2C H2.defaultSettings rinfoHostName rinfoPortNumber $
        doHTTP "H2C" ident path lim ri q qctl

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
                Nothing -> return $ toResult ri proto $ Reply msg tx rx
                Just err -> E.throwIO err
  where
    ~tag =
        "    query "
            ++ show qname
            ++ " "
            ++ show qtype
            ++ " to "
            ++ rinfoHostName
            ++ "#"
            ++ show rinfoPortNumber
            ++ "/"
            ++ proto
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
