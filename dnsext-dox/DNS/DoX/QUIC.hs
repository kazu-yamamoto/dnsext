{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.QUIC where

import Codec.Serialise
import DNS.Do53.Internal
import DNS.Types.Decode
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal hiding (Recv, shared)
import qualified Network.TLS as TLS

import DNS.DoX.HTTP2
import DNS.DoX.Imports
import DNS.DoX.SAN

quicPersistentResolver :: PersistentResolver
quicPersistentResolver ri body = toDNSError "quicPersistentResolver" $ run cc $ \conn -> do
    body $ resolv conn ri
    saveResumptionInfo conn ri tag
  where
    tag = nameTag ri "QUIC"
    cc = getQUICParams ri tag "doq"

quicResolver :: OneshotResolver
quicResolver ri q qctl = toDNSError "quicResolver" $ run cc $ \conn -> withTimeout ri $ do
    res <- resolv conn ri q qctl
    saveResumptionInfo conn ri tag
    return res
  where
    tag = nameTag ri "QUIC"
    cc = getQUICParams ri tag "doq"

resolv :: Connection -> ResolveInfo -> Resolver
resolv conn ri@ResolveInfo{..} q qctl = do
    strm <- stream conn
    ident <- ractionGenId rinfoActions
    let qry = encodeQuery ident q qctl
        tx = BS.length qry
    sendVC (sendStreamMany strm) qry
    shutdownStream strm
    bs <- recvVC rinfoVCLimit $ recvStream strm 2048
    now <- getTime
    case decodeAt now bs of
        Left e -> return $ Left e
        Right msg -> case checkRespM q ident msg of -- fixme
            Nothing -> return $ Right $ Reply tag msg tx $ BS.length bs
            Just err -> return $ Left err
  where
    getTime = ractionGetTime rinfoActions
    tag = nameTag ri "QUIC"

saveResumptionInfo :: Connection -> ResolveInfo -> NameTag -> IO ()
saveResumptionInfo conn ResolveInfo{..} tag = do
    rinfo <- getResumptionInfo conn
    when (isResumptionPossible rinfo) $ do
        let bs = BL.toStrict $ serialise rinfo
        ractionOnResumptionInfo rinfoActions tag bs

getQUICParams :: ResolveInfo -> NameTag -> ByteString -> ClientConfig
getQUICParams ResolveInfo{..} tag alpn0 =
    defaultClientConfig
        { ccServerName = show rinfoIP
        , -- TLS SNI
          ccServerNameOverride = rinfoServerName
        , ccPortName = show rinfoPort
        , ccALPN = \_ -> return $ Just [alpn0]
        , ccDebugLog = False
        , ccValidate = ractionValidate rinfoActions
        , ccOnServerCertificate = makeOnServerCertificate $ ractionServerAltName rinfoActions
        , ccResumption = rinfo
        , ccUse0RTT = ractionUseEarlyData rinfoActions
        , ccKeyLog = ractionKeyLog rinfoActions
        , ccHooks =
            defaultHooks
                { onConnectionEstablished = \i -> do
                    let ~ver = if version i == Version1 then "v1" else "v2"
                        ~mode = case handshakeMode i of
                            TLS.PreSharedKey -> "Resumption"
                            TLS.RTT0 -> "0-RTT"
                            x -> show x
                        ~msg = ver ++ "(" ++ mode ++ ")"
                    ractionOnConnectionInfo rinfoActions tag msg
                }
        }
  where
    rinfo = case ractionResumptionInfo rinfoActions tag of
        [] -> defaultResumptionInfo
        r : _ -> case deserialiseOrFail $ BL.fromStrict r of
            Left _ -> defaultResumptionInfo
            Right x -> x
