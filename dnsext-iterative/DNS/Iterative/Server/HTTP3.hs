{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP3 (
    http3Server,
) where

-- GHC packages

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
import DNS.Iterative.Stats (incStatsDoH3)

----------------------------------------------------------------
http3Server :: VcServerConfig -> Server
http3Server VcServerConfig{..} env toCacher port host = do
    let http3server = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            withLoc $ QUIC.run sconf $ \conn ->
                withLoc $ H3.run conn (conf mgr) $ doHTTP env toCacher
    return [http3server]
  where
    withLoc = withLocationIOE (show host ++ ":" ++ show port ++ "/h3")
    sconf = getServerConfig vc_credentials vc_session_manager host port "h3"
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
    (toSender, fromX) <- mkConnector
    einp <- getInput req
    incStatsDoH3 (sockAddrInet6 peersa) (stats_ env)
    case einp of
        Left emsg -> logLn env Log.WARN $ "decode-error: " ++ emsg
        Right bs -> do
            let inp = Input bs mysa peerInfo DOH toSender
            toCacher inp
            Output bs' _ <- fromX
            let header = mkHeader bs'
                response = H2.responseBuilder HT.ok200 header $ byteString bs'
            sendResponse response []
  where
    -- fixme record
    mkHeader bs =
        [ (HT.hContentType, "application/dns-message")
        , (HT.hContentLength, C8.pack $ show $ C8.length bs)
        ]
