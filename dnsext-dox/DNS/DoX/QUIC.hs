{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.QUIC where

import DNS.Do53.Internal
import Network.Socket hiding (recvBuf)
import Network.QUIC
import Network.QUIC.Client

import DNS.DoX.Common

doq :: HostName -> PortNumber -> WireFormat -> IO ()
doq hostname port qry = run cc $ \conn -> do
    strm <- stream conn
    let sendDoQ = sendVC $ sendStreamMany strm
        recvDoQ = recvVC $ recvStream strm
    sendDoQ qry
    shutdownStream strm
    res <- recvDoQ
    print res
  where
    cc = getQUICParams hostname port "doq"
