{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.QUIC where

import DNS.Do53.Internal
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal hiding (Recv, shared)
import Network.Socket

import DNS.DoX.Imports

quicPersistentResolver :: PersistentResolver
quicPersistentResolver ri@ResolveInfo{..} body = run cc $ \conn -> do
    strm <- stream conn
    let sendDoQ bs = do
            sendVC (sendStreamMany strm) bs
            shutdownStream strm
        recvDoQ = recvVC rinfoVCLimit $ recvStream strm
    vcPersistentResolver "QUIC" sendDoQ recvDoQ ri body
  where
    cc = getQUICParams rinfoIP rinfoPort "doq"

quicResolver :: OneshotResolver
quicResolver ri@ResolveInfo{..} q qctl = run cc $ \conn -> do
    strm <- stream conn
    let sendDoQ bs = do
            sendVC (sendStreamMany strm) bs
            shutdownStream strm
        recvDoQ = recvVC rinfoVCLimit $ recvStream strm
    vcResolver "QUIC" sendDoQ recvDoQ ri q qctl
  where
    cc = getQUICParams rinfoIP rinfoPort "doq"

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
