{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import DNS.Do53.Internal
import Data.ByteString.Char8 ()
import qualified Network.HTTP2.TLS.Client as H2
import Network.Socket.BufferPool (makeRecvN)

tlsResolver :: VCLimit -> Resolver
tlsResolver lim ri@ResolvInfo{..} q qctl = vcResolver "TLS" perform ri q qctl
  where
    -- Using a fresh connection
    perform solve = H2.runTLS H2.defaultSettings rinfoHostName rinfoPortNumber "dot" solve'
      where
        solve' _mgr backend = do
            recvN <- makeRecvN "" $ H2.recv backend
            let sendDoT = sendVC $ H2.sendMany backend
                recvDoT = recvVC lim recvN
            solve sendDoT recvDoT
