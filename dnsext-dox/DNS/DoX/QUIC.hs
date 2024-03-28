{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.QUIC where

import DNS.Do53.Internal
import DNS.Types.Decode
import qualified Data.ByteString as BS
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal hiding (Recv, shared)
import Network.Socket

import DNS.DoX.Imports

quicPersistentResolver :: PersistentResolver
quicPersistentResolver ri@ResolveInfo{..} body = run cc $ \conn -> do
    body $ resolv conn ri
  where
    cc = getQUICParams rinfoIP rinfoPort "doq"

quicResolver :: OneshotResolver
quicResolver ri@ResolveInfo{..} q qctl = run cc $ \conn -> do
    resolv conn ri q qctl
  where
    cc = getQUICParams rinfoIP rinfoPort "doq"

resolv :: Connection -> ResolveInfo -> Resolver
resolv conn ri@ResolveInfo{..} q qctl = do
    strm <- stream conn
    ident <- ractionGenId rinfoActions
    let qry = encodeQuery ident q qctl
        tx = BS.length qry
    sendVC (sendStreamMany strm) qry
    shutdownStream strm
    (rx, bss) <- recvVC rinfoVCLimit $ recvStream strm
    now <- getTime
    case decodeChunks now bss of
        Left e -> return $ Left e
        Right msg -> case checkRespM q ident msg of -- fixme
            Nothing -> return $ Right $ toResult ri "doq" $ Reply msg tx rx
            Just err -> return $ Left err
  where
    getTime = ractionGetTime rinfoActions

getQUICParams :: IP -> PortNumber -> ByteString -> ClientConfig
getQUICParams addr port alpn =
    defaultClientConfig
        { ccServerName = show addr
        , ccPortName = show port
        , ccALPN = \_ -> return $ Just [alpn]
        , ccDebugLog = False
        , ccValidate = False
        , ccVersions = [Version1]
        }
