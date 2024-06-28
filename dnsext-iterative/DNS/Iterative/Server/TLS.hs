{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TLS where

-- GHC packages

import qualified Data.ByteString as BS
import Data.Functor

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import qualified Network.HTTP2.TLS.Server as H2
import Network.Socket.BufferPool (makeRecvN)

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsDoT, sessionStatsDoT)

tlsServers :: VcServerConfig -> ServerActions
tlsServers conf env toCacher ss =
    concat <$> mapM (tlsServer conf env toCacher) ss

tlsServer :: VcServerConfig -> Env -> ToCacher -> Socket -> IO ([IO ()])
tlsServer VcServerConfig{..} env toCacher s = do
    name <- socketName s
    let tlsserver = withLocationIOE name $ H2.runTLSWithListenSocket settings vc_credentials s "dot" $ go
    return [tlsserver]
  where
    maxSize = fromIntegral vc_query_max_size
    settings =
        H2.defaultSettings
            { H2.settingsTimeout = vc_idle_timeout
            , H2.settingsSlowlorisSize = vc_slowloris_size
            , H2.settingsSessionManager = vc_session_manager
            , H2.settingsEarlyDataSize = vc_early_data_size
            }
    go _ backend = sessionStatsDoT (stats_ env) $ do
        let mysa = H2.mySockAddr backend
            peersa = H2.peerSockAddr backend
            peerInfo = PeerInfoVC peersa
        recvN <- makeRecvN "" $ H2.recv backend
        (toSender, fromX) <- mkConnector
        let recv = do
                (siz, bss) <- DNS.recvVC maxSize recvN
                if siz == 0
                    then return ("", peerInfo)
                    else incStatsDoT peersa (stats_ env) $> (BS.concat bss, peerInfo)
            send bs _ = DNS.sendVC (H2.sendMany backend) bs
            receiver = receiverLogicVC env mysa recv toCacher toSender DOT
            sender = senderLogicVC env send fromX
        TStat.concurrently_ "tls-send" sender "tls-recv" receiver
