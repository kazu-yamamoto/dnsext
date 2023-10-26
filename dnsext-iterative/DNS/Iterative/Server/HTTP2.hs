{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP2 where

-- GHC packages
import qualified Data.ByteString as BS
import Data.ByteString.Builder (byteString)

-- dnsext-* packages
import DNS.Do53.Internal
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import DNS.Types (defaultResponse)
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS

-- other packages
import qualified Network.HTTP.Types as HT
import qualified Network.HTTP2.Server as H2
import qualified Network.HTTP2.TLS.Server as H2TLS
import Network.TLS (Credentials (..))
import Data.ByteString.Base64.URL

-- this package
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types

----------------------------------------------------------------
http2Server :: Credentials -> VcServerConfig -> Server
http2Server creds VcServerConfig{..} env toCacher port host = do
    let http2server = H2TLS.run settings creds host port $ doHTTP env toCacher
    return [http2server]
  where
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
            }

newtype Http2cServerConfig = Http2cServerConfig
    { http2c_idle_timeout :: Int
    }

http2cServer :: VcServerConfig -> Server
http2cServer VcServerConfig{..} env toCacher port host = do
    let http2server = H2TLS.runH2C settings host port $ doHTTP env toCacher
    return [http2server]
  where
    settings =
        H2TLS.defaultSettings
            { H2TLS.settingsTimeout = vc_idle_timeout
            , H2TLS.settingsSlowlorisSize = vc_slowloris_size
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
      Right inp -> case DNS.decode inp of
        Right queryMsg -> do
            let fuel = Fuel queryMsg defaultResponse mysa peerInfo DOH toSender
            toCacher fuel
            rep <- fromX
            let bs = DNS.encode $ fuelReply rep
            let response = H2.responseBuilder HT.ok200 header $ byteString bs
            sendResponse response []
            -- fixme record
        Left e -> do
            logLn env Log.WARN $ "decode-error: " ++ show e
  where
    header = [(HT.hContentType, "application/dns-message")]

getInput :: H2.Request -> IO (Either String BS.ByteString)
getInput req
  | method == Just "GET" = case H2.requestPath req of
      Just path | "/dns-query?dns=" `BS.isPrefixOf` path -> return $ Right $ decodeBase64Lenient$ BS.drop 15 path
      _ -> return $ Left "illegal URL"
  | method == Just "POST" = do
        (_rx, rqs) <- recvManyN (H2.getRequestBodyChunk req) 2048
        return $ Right $ BS.concat rqs
  | otherwise = return $ Left "illegal method"
  where
    method = H2.requestMethod req
