{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import DNS.Do53.Internal
import Data.ByteString.Char8 ()
import qualified Network.HTTP2.TLS.Client as H2
import qualified Network.HTTP2.TLS.Internal as H2
import Network.Socket.BufferPool (makeRecvN)

tlsResolver :: VCLimit -> OneshotResolver
tlsResolver lim ri@ResolveInfo{..} q qctl =
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        recvN <- makeRecvN "" $ H2.recvTLS ctx
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC lim recvN
        vcResolver "TLS" sendDoT recvDoT ri q qctl
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
            }
