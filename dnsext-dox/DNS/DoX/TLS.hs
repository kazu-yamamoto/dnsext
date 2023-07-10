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
    perform solve = H2.runTLS rinfoHostName rinfoPortNumber "dot" f
      where
        f H2.IOBackend{..} = do
            recvN <- makeRecvN "" recv
            let sendDoT = sendVC sendMany
                recvDoT = recvVC lim recvN
            solve sendDoT recvDoT
