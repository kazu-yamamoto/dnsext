{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.QUIC where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.Types
import Network.Socket hiding (recvBuf)
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal

doq :: HostName -> PortNumber -> Question -> IO ()
doq hostname port q = run cc $ \conn -> do
    strm <- stream conn
    let sendDoQ = sendVC $ sendStreamMany strm
        recvDoQ = recvVC $ recvStream strm
    let qry = encodeQuery 100 q mempty
    sendDoQ qry
    shutdownStream strm
    res <- recvDoQ
    print res
  where
    cc = defaultClientConfig {
        ccServerName = hostname
      , ccPortName   = show port
      , ccALPN       = \_ -> return $ Just ["doq"]
      , ccDebugLog   = True
      , ccValidate   = False
      , ccVersions   = [Version1]
      }
