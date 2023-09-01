{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.TLS where

-- GHC packages

import Data.ByteString.Char8 ()

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import DNS.TAP.Schema (SocketProtocol(..))

-- other packages
import qualified Network.HTTP2.TLS.Server as H2
import Network.Socket.BufferPool (makeRecvN)
import Network.TLS (Credentials (..))

-- this package
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.Types

tlsServer :: Credentials -> VcServerConfig -> Server
tlsServer creds VcServerConfig{..} env port host = do
    (cntget, cntinc) <- newCounters
    let tlsserver = H2.runTLS settings creds host port "dot" $ \_ backend -> do
            recvN <- makeRecvN "" $ H2.recv backend
            let sendDoT = DNS.sendVC $ H2.sendMany backend
                recvDoT = DNS.recvVC maxSize recvN
            (_n, bss) <- recvDoT
            let mysa = H2.mySockAddr backend
                peersa = H2.peerSockAddr backend
            cacheWorkerLogic env cntinc sendDoT DOT mysa peersa bss
    return ([tlsserver], [readCounters cntget])
  where
    maxSize = fromIntegral vc_query_max_size
    settings =
        H2.defaultSettings
            { H2.settingsTimeout = vc_idle_timeout
            , H2.settingsSlowlorisSize = vc_slowloris_size
            }
