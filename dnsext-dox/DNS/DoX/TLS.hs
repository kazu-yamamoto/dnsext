{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import Codec.Serialise
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as BL
import Data.Either (rights)
import qualified Network.HTTP2.TLS.Client as H2
import qualified Network.HTTP2.TLS.Internal as H2
import Network.TLS
import System.X509

import DNS.Do53.Internal

tlsPersistentResolver :: PersistentResolver
tlsPersistentResolver ri@ResolveInfo{..} body = do
    settings <- makeSettings ri tag
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit $ H2.recvTLS ctx
        vcPersistentResolver tag sendDoT recvDoT ri body
  where
    tag = nameTag ri "TLS"

makeSettings :: ResolveInfo -> NameTag -> IO H2.Settings
makeSettings ResolveInfo{..} tag = do
    caStore <- if ractionValidate rinfoActions then getSystemCertificateStore else return mempty
    return $
        H2.defaultSettings
            { H2.settingsValidateCert = ractionValidate rinfoActions
            , H2.settingsCAStore = caStore
            , H2.settingsUseEarlyData = ractionUseEarlyData rinfoActions
            , H2.settingsKeyLogger = ractionKeyLog rinfoActions
            , H2.settingsWantSessionResumeList =
                rights (deserialiseOrFail . BL.fromStrict <$> ractionResumptionInfo rinfoActions tag)
            , H2.settingsSessionManager =
                noSessionManager
                    { sessionEstablish = \sid sd -> do
                        let bs = BL.toStrict $ serialise (sid, sd)
                        ractionOnResumptionInfo rinfoActions tag bs
                        return Nothing
                    }
            , H2.settingsOnServerFinished = \i -> do
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
tlsResolver ri@ResolveInfo{..} q qctl =
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit $ H2.recvTLS ctx
        vcResolver "TLS" sendDoT recvDoT ri q qctl
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
            }
