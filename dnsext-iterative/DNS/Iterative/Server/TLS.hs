{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TLS where

-- GHC packages
import Data.Functor
import qualified Data.ByteString as BS

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

tlsServer :: VcServerConfig -> Server
tlsServer VcServerConfig{..} env toCacher port host = do
    let tlsserver = withLoc $ H2.runTLS settings vc_credentials host port "dot" $ go
    return [tlsserver]
  where
    withLoc = withLocationIOE (show host ++ ":" ++ show port ++ "/dot")
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
        (toSender, fromX, availX) <- mkConnector
        (vcEOF, vcPendings) <- mkVcState
        let recv = do
                (siz, bss) <- DNS.recvVC maxSize recvN
                if siz == 0
                    then return ("", peerInfo)
                    else incStatsDoT peersa (stats_ env) $> (BS.concat bss, peerInfo)
            send bs _ = DNS.sendVC (H2.sendMany backend) bs
            receiver = receiverLoopVC env vcEOF vcPendings mysa recv toCacher toSender DOT
            sender = senderLoopVC "tls-send" env vcEOF vcPendings availX send fromX
        TStat.concurrently_ "tls-send" sender "tls-recv" receiver
        logLn env Log.DEBUG $ "tls-srv: close: " ++ show peersa
