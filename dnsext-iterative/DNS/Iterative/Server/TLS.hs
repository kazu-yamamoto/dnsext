{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TLS (
    tlsServers,
)
where

-- GHC packages

import qualified Data.ByteString as BS
import Data.Functor

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import qualified DNS.Log as Log
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

tlsServer :: VcServerConfig -> Env -> (ToCacher -> IO ()) -> Socket -> IO ([IO ()])
tlsServer VcServerConfig{..} env toCacher s = do
    name <- socketName s <&> (++ "/tls")
    let tlsserver = withLocationIOE name $ H2.runTLSWithSocket settings vc_credentials s "dot" $ go
    return [tlsserver]
  where
    tmicro = vc_idle_timeout * 1_000_000
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
        logLn env Log.DEBUG $ "tls-srv: accept: " ++ show peersa
        recvN <- makeRecvN "" $ H2.recv backend
        let recv = do
                (siz, bss) <- DNS.recvVC maxSize recvN
                if siz == 0
                    then return ("", peerInfo)
                    else incStatsDoT peersa (stats_ env) $> (BS.concat bss, peerInfo)
            send bs _ = DNS.sendVC (H2.sendMany backend) bs
        withVcSession (pure $ pure ()) tmicro vc_slowloris_size $ \(vcSess, toSender, fromX) -> do
            let receiver = receiverVC "tls-recv" env vcSess recv toCacher $ mkInput mysa toSender DOT
                sender = senderVC "tls-send" env vcSess send fromX
            TStat.concurrently_ "tls-send" sender "tls-recv" receiver
        logLn env Log.DEBUG $ "tls-srv: close: " ++ show peersa
