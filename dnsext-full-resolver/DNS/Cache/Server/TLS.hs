{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.TLS where

-- GHC packages

import Data.ByteString.Char8 ()

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS

-- other packages
import qualified Network.HTTP2.TLS.Server as H2
import Network.Socket.BufferPool (makeRecvN)
import Network.TLS (Credentials (..))

-- this package
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.Types

----------------------------------------------------------------
data TlsServerConfig = TlsServerConfig
    { tls_idle_timeout :: Int
    }

tlsServer :: Credentials -> TlsServerConfig -> Server
tlsServer creds TlsServerConfig{..} env port host = do
    (cntget, cntinc) <- newCounters
    let tlsserver = H2.runTLS settings creds host port "dot" $ \_ backend -> do
            recvN <- makeRecvN "" $ H2.recv backend
            let sendDoT = DNS.sendVC $ H2.sendMany backend
                recvDoT = DNS.recvVC 2048 recvN
            (_n, bss) <- recvDoT
            cacheWorkerLogic env cntinc sendDoT bss
    return ([tlsserver], [readCounters cntget])
  where
    settings =
        H2.defaultSettings
            { H2.settingsTimeout = tls_idle_timeout
            }
