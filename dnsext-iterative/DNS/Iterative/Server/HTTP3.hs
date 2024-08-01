{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP3 (
    http3Servers,
) where

-- GHC packages
import Control.Monad (when)
import Data.ByteString.Builder (byteString)
import qualified Data.ByteString.Char8 as C8

-- dnsext-* packages
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages

import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import qualified Network.HTTP3.Server as H3
import qualified Network.QUIC.Server as QUIC
import qualified System.TimeManager as T

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.Types
import DNS.Iterative.Server.UDP
import DNS.Iterative.Stats (incStatsDoH3)

----------------------------------------------------------------
http3Servers :: VcServerConfig -> ServerActions
http3Servers VcServerConfig{..} env toCacher ss = do
    -- fixme: withLocationIOE naming
    when vc_interface_automatic $ mapM_ setPktInfo ss
    let http3server = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            withLocationIOE "h3" $ QUIC.runWithSockets ss sconf $ \conn ->
                H3.run conn (conf mgr) $ doHTTP env toCacher
    return [http3server]
  where
    sconf = getServerConfig vc_credentials vc_session_manager "h3"
    conf mgr =
        H3.Config
            { confHooks = H3.defaultHooks
            , confTimeoutManager = mgr
            , confPositionReadMaker = H3.defaultPositionReadMaker
            }

doHTTP
    :: Env
    -> ToCacher
    -> H2.Server
doHTTP env toCacher req aux sendResponse = do
    let mysa = H2.auxMySockAddr aux
        peersa = H2.auxPeerSockAddr aux
        peerInfo = PeerInfoVC peersa
    (toSender, fromX, _) <- mkConnector
    einp <- getInput req
    case einp of
        Left emsg -> logLn env Log.WARN $ "decode-error: " ++ emsg
        Right bs -> do
            let inp = Input bs 0 mysa peerInfo DOH toSender
            incStatsDoH3 peersa (stats_ env)
            toCacher inp
            Output bs' _ _ <- fromX
            let header = mkHeader bs'
                response = H2.responseBuilder HT.ok200 header $ byteString bs'
            sendResponse response []
  where
    -- fixme record
    mkHeader bs =
        [ (HT.hContentType, "application/dns-message")
        , (HT.hContentLength, C8.pack $ show $ C8.length bs)
        ]
