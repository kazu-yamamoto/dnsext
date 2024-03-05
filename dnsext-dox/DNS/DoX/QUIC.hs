{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.QUIC where

import DNS.Do53.Internal
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal hiding (Recv, shared)
import Network.Socket

import DNS.DoX.Imports

quicResolver :: VCLimit -> Resolver
quicResolver lim ri@ResolveInfo{..} q qctl = vcResolver "QUIC" perform ri q qctl
  where
    cc = getQUICParams rinfoHostName rinfoPortNumber "doq"
    perform solve = run cc $ \conn -> do
        strm <- stream conn
        let sendDoQ bs = do
                sendVC (sendStreamMany strm) bs
                shutdownStream strm
            recvDoQ = recvVC lim $ recvStream strm
        solve sendDoQ recvDoQ

getQUICParams :: HostName -> PortNumber -> ByteString -> ClientConfig
getQUICParams hostname port alpn =
    defaultClientConfig
        { ccServerName = hostname
        , ccPortName = show port
        , ccALPN = \_ -> return $ Just [alpn]
        , ccDebugLog = False
        , ccValidate = False
        , ccVersions = [Version1]
        }
