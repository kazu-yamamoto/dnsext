{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import DNS.Do53.Internal
import Data.ByteString.Char8 ()
import qualified Network.HTTP2.TLS.Client as H2
import qualified Network.HTTP2.TLS.Internal as H2
import Network.Socket.BufferPool (makeRecvN)

withTlsResolver :: PersistentResolver
withTlsResolver ri@ResolveInfo{..} body =
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        recvN <- makeRecvN "" $ H2.recvTLS ctx
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit recvN
        withVCResolver "TLS" sendDoT recvDoT ri body
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
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
