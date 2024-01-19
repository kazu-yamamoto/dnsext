{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP2 (
    http2Server,
    http2cServer,
    VcServerConfig (..),
    getInput,
) where

-- GHC packages
import Control.Monad (forever)
import qualified Data.ByteString as BS
import Data.ByteString.Builder (byteString)

-- dnsext-* packages
import DNS.Do53.Internal
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import Data.ByteString.Base64.URL
import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import Network.HTTP2.TLS.Server (ServerIO (..))
import qualified Network.HTTP2.TLS.Server as H2TLS
import Network.TLS (Credentials (..))

-- this package
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

----------------------------------------------------------------
http2Server :: Credentials -> VcServerConfig -> Server
http2Server creds VcServerConfig{..} env toCacher port host = do
    let http2server = H2TLS.runIO settings creds host port $ doHTTP "h2" env toCacher
    return [http2server]
  where
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
            }

http2cServer :: VcServerConfig -> Server
http2cServer VcServerConfig{..} env toCacher port host = do
    let http2server = H2TLS.runIOH2C settings host port $ doHTTP "h2c" env toCacher
    return [http2server]
  where
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
            }

doHTTP
    :: String -> Env -> ToCacher -> ServerIO -> IO (IO ())
doHTTP name env toCacher ServerIO{..} = do
    (toSender, fromX) <- mkConnector
    let receiver = forever $ do
            (_, strm, req) <- sioReadRequest
            let peerInfo = PeerInfoH2 sioPeerSockAddr strm
            einp <- getInput req
            case einp of
                Left emsg -> logLn env Log.WARN $ "decode-error: " ++ emsg
                Right bs -> do
                    let inp = Input bs sioMySockAddr peerInfo DOH toSender
                    toCacher inp
        sender = forever $ do
            Output bs' (PeerInfoH2 _ strm) <- fromX
            let response = H2.responseBuilder HT.ok200 header $ byteString bs'
            sioWriteResponse strm response
    return $ TStat.concurrently_ (name ++ "-send") sender (name ++ "-recv") receiver
  where
    header = [(HT.hContentType, "application/dns-message")]

getInput :: H2.Request -> IO (Either String BS.ByteString)
getInput req
    | method == Just "GET" = case H2.requestPath req of
        Just path | "/dns-query?dns=" `BS.isPrefixOf` path -> return $ Right $ decodeBase64Lenient $ BS.drop 15 path
        _ -> return $ Left "illegal URL"
    | method == Just "POST" = do
        (_rx, rqs) <- recvManyN (H2.getRequestBodyChunk req) 2048
        return $ Right $ BS.concat rqs
    | otherwise = return $ Left "illegal method"
  where
    method = H2.requestMethod req
