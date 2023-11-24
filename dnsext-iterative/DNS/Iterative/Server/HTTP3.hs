{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP3 (
    http3Server,
) where

-- GHC packages

import Data.ByteString.Builder (byteString)
import Data.ByteString.Char8 ()

-- dnsext-* packages
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages

import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import qualified Network.HTTP3.Server as H3
import qualified Network.QUIC.Server as QUIC
import Network.TLS (Credentials (..))
import qualified System.TimeManager as T

-- this package

import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.Types

----------------------------------------------------------------
http3Server :: Credentials -> VcServerConfig -> Server
http3Server creds VcServerConfig{..} env toCacher port host = do
    let http3server = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            QUIC.run sconf $ \conn ->
                H3.run conn (conf mgr) $ doHTTP env toCacher
    return [http3server]
  where
    sconf = getServerConfig creds host port "h3"
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
    case einp of
        Left emsg -> logLn env Log.WARN $ "decode-error: " ++ emsg
        Right bs -> do
            let inp = Input bs mysa peerInfo DOH toSender
            toCacher inp
            Output bs' _ <- fromX
            let response = H2.responseBuilder HT.ok200 header $ byteString bs'
            sendResponse response []
  where
    -- fixme record

    header = [(HT.hContentType, "application/dns-message")]
