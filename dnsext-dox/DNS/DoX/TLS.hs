{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.TLS where

import DNS.Do53.Internal
import Data.ByteString.Char8 ()
import Network.Socket hiding (recvBuf)
import Network.Socket.BufferPool
import Network.TLS (contextNew, handshake, bye)
import qualified UnliftIO.Exception as E

import DNS.DoX.Common

dot :: HostName -> PortNumber -> WireFormat -> IO ()
dot hostname port qry = do
    E.bracket open close $ \sock ->
      E.bracket (contextNew sock params) bye $ \ctx -> do
        handshake ctx
        (recv, recvBuf) <- makeRecv $ recvTLS ctx
        recvN <- makeReceiveN "" recv recvBuf
        let sendDoT = sendVC (sendManyTLS ctx)
            recvDoT = recvVC recvN
        sendDoT qry
        res <- recvDoT
        print res
  where
    params = getTLSParams hostname "dot" False
    open = do
        ai <- makeAddrInfo (Just hostname) port
        sock <- openSocket ai

        let sockaddr = addrAddress ai
        connect sock sockaddr
        return sock
