{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import Codec.Serialise
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as BL
import Data.Either (rights)
import qualified Network.HTTP2.TLS.Client as H2TLS
import qualified Network.HTTP2.TLS.Internal as H2TLS
import Network.TLS

import DNS.Do53.Internal
import DNS.DoX.Imports

import DNS.DoX.SAN

tlsPersistentResolver :: PersistentResolver
tlsPersistentResolver ri@ResolveInfo{..} body = toDNSError "tlsPersistentResolver" $ do
    -- Using a fresh connection
    H2TLS.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        let sendDoT = sendVC $ H2TLS.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit $ H2TLS.recvTLS ctx
        vcPersistentResolver tag sendDoT recvDoT ri body
  where
    tag = nameTag ri "TLS"
    settings = makeSettings ri tag

makeSettings :: ResolveInfo -> NameTag -> H2TLS.Settings
makeSettings ResolveInfo{..} tag =
    H2TLS.defaultSettings
        { H2TLS.settingsValidateCert = ractionValidate rinfoActions
        , H2TLS.settingsOnServerCertificate = makeOnServerCertificate $ ractionServerAltName rinfoActions
        , H2TLS.settingsUseEarlyData = ractionUseEarlyData rinfoActions
        , -- TLS SNI
          H2TLS.settingsServerNameOverride = rinfoServerName
        , H2TLS.settingsKeyLogger = ractionKeyLog rinfoActions
        , H2TLS.settingsWantSessionResumeList =
            rights (deserialiseOrFail . BL.fromStrict <$> ractionResumptionInfo rinfoActions tag)
        , H2TLS.settingsSessionManager =
            noSessionManager
                { sessionEstablish = \sid sd -> do
                    let bs = BL.toStrict $ serialise (sid, sd)
                    ractionOnResumptionInfo rinfoActions tag bs
                    return Nothing
                }
        , H2TLS.settingsOnServerFinished = \i -> do
            let ~ver = if infoVersion i == TLS13 then "v1.3" else "v1.2"
                ~mode = case infoTLS13HandshakeMode i of
                    Nothing -> if infoTLS12Resumption i then "Resumption" else "FullHandshake"
                    Just PreSharedKey -> "Resumption"
                    Just RTT0 -> "0-RTT"
                    Just x -> show x
                ~msg = ver ++ "(" ++ mode ++ ")"
            ractionOnConnectionInfo rinfoActions tag msg
        }

tlsResolver :: OneshotResolver
tlsResolver ri@ResolveInfo{..} q qctl = toDNSError "tlsResolver" $ do
    -- Using a fresh connection
    H2TLS.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        let sendDoT = sendVC $ H2TLS.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit $ H2TLS.recvTLS ctx
        vcResolver tag sendDoT recvDoT ri q qctl
  where
    tag = nameTag ri "TLS"
    settings = makeSettings ri tag
