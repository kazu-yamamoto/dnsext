{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.QUIC where

-- GHC packages
import Control.Concurrent.STM (isEmptyTQueue)
import qualified Data.ByteString as BS

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import qualified Network.QUIC as QUIC
import qualified Network.QUIC.Internal as QUIC
import Network.QUIC.Server (ServerConfig (..))
import qualified Network.QUIC.Server as QUIC
import Network.TLS (Credentials (..), SessionManager)

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP
import DNS.Iterative.Stats (incStatsDoQ, sessionStatsDoQ)

----------------------------------------------------------------

quicServers :: VcServerConfig -> ServerActions
quicServers VcServerConfig{..} env toCacher ss = do
    -- fixme: withLocationIOE naming
    when vc_interface_automatic $ mapM_ setPktInfo ss
    let quicserver = withLocationIOE "QUIC" $ QUIC.runWithSockets ss sconf go
    return [quicserver]
  where
    tmicro = vc_idle_timeout * 1_000_000
    sconf = getServerConfig vc_credentials vc_session_manager "doq" (vc_idle_timeout * 1_000 + quicDeferMills)
    quicDeferMills = 20 {- deferral until an exception is raised from quic library -}
    maxSize = fromIntegral vc_query_max_size
    go conn = sessionStatsDoQ (stats_ env) $ do
        info <- QUIC.getConnectionInfo conn
        let mysa = QUIC.localSockAddr info
            peersa = QUIC.remoteSockAddr info
            waitInput = pure $ (guard . not =<<) . isEmptyTQueue $ QUIC.inputQ conn
        (vcSess, toSender, fromX) <- initVcSession waitInput tmicro vc_slowloris_size
        let recv = do
                strm <- QUIC.acceptStream conn
                let peerInfo = PeerInfoQUIC peersa strm
                -- Without a designated thread, recvStream would block.
                (siz, bss) <- DNS.recvVC maxSize $ QUIC.recvStream strm
                if siz == 0
                    then return ("", peerInfo)
                    else incStatsDoQ peersa (stats_ env) $> (BS.concat bss, peerInfo)
            send bs peerInfo = do
                case peerInfo of
                    PeerInfoQUIC _ strm -> DNS.sendVC (QUIC.sendStreamMany strm) bs >> QUIC.closeStream strm
                    _ -> return ()
            receiver = receiverVC "quic-recv" env vcSess recv toCacher $ mkInput mysa toSender DOQ
            sender = senderVC "quic-send" env vcSess send fromX
        TStat.concurrently_ "quic-send" sender "quic-recv" receiver

getServerConfig :: Credentials -> SessionManager -> ByteString -> Int -> ServerConfig
getServerConfig creds sm alpn tmills =
    QUIC.defaultServerConfig
        { scALPN = Just (\_ bss -> if alpn `elem` bss then return alpn else return "")
        , scCredentials = creds
        , scUse0RTT = True
        , scSessionManager = sm
        , QUIC.scParameters = (QUIC.scParameters QUIC.defaultServerConfig){QUIC.maxIdleTimeout = fromIntegral tmills}
        }
