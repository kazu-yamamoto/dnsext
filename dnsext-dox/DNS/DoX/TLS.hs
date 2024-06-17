{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import Codec.Serialise
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as BL
import qualified Network.HTTP2.TLS.Client as H2
import qualified Network.HTTP2.TLS.Internal as H2
import Network.Socket.BufferPool (makeRecvN)
import Network.TLS

import DNS.Do53.Internal

tlsPersistentResolver :: PersistentResolver
tlsPersistentResolver ri@ResolveInfo{..} body =
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        recvN <- makeRecvN "" $ H2.recvTLS ctx
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit recvN
        vcPersistentResolver tag sendDoT recvDoT ri body
  where
    tag = nameTag ri "TLS"
    settings = makeSettings ri tag

makeSettings :: ResolveInfo -> NameTag -> H2.Settings
makeSettings ResolveInfo{..} tag =
    H2.defaultSettings
        { H2.settingsValidateCert = False
        , H2.settingsUseEarlyData = ractionUseEarlyData rinfoActions
        , H2.settingsKeyLogger = ractionKeyLog rinfoActions
        , H2.settingsWantSessionResume = case ractionResumptionInfo rinfoActions tag of
            Nothing -> Nothing
            Just r -> case deserialiseOrFail $ BL.fromStrict r of
                Left _ -> Nothing
                Right x -> Just x
        , H2.settingsSessionManager =
            noSessionManager
                { sessionEstablish = \sid sd -> do
                    let bs = BL.toStrict $ serialise (sid, sd)
                    ractionOnResumptionInfo rinfoActions tag bs
                    return Nothing
                }
        , H2.settingsOnServerFinished = \Information{..} -> do
            let ~ver = if infoVersion == TLS13 then "v1.3" else "v1.2"
                ~mode = case infoTLS13HandshakeMode of
                    Nothing -> if infoTLS12Resumption then "Resumption" else "FullHandshake"
                    Just PreSharedKey -> "Resumption"
                    Just RTT0 -> "0-RTT"
                    Just x -> show x
                ~msg = ver ++ "(" ++ mode ++ ")"
            ractionOnConnectionInfo rinfoActions tag msg
        }

tlsResolver :: OneshotResolver
tlsResolver ri@ResolveInfo{..} q qctl =
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        recvN <- makeRecvN "" $ H2.recvTLS ctx
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit recvN
        vcResolver "TLS" sendDoT recvDoT ri q qctl
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
            }
