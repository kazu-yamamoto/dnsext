{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import DNS.Do53.Internal
import Data.ByteString.Char8 ()
import qualified Network.HTTP2.TLS.Client as H2
import qualified Network.HTTP2.TLS.Internal as H2
import Network.Socket.BufferPool (makeRecvN)

tlsResolver :: VCLimit -> Resolver
tlsResolver lim ri@ResolvInfo{..} q qctl = vcResolver "TLS" perform ri q qctl
  where
    -- Using a fresh connection
    perform solve = H2.runTLS settings rinfoHostName rinfoPortNumber "dot" solve'
      where
        settings =
            H2.defaultSettings
                { H2.settingsValidateCert = False
                }
        solve' ctx _ _ = do
            recvN <- makeRecvN "" $ H2.recvTLS ctx
            let sendDoT = sendVC $ H2.sendManyTLS ctx
                recvDoT = recvVC lim recvN
            solve sendDoT recvDoT
