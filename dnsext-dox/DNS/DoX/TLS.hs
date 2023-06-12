{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import DNS.Do53.Internal
import DNS.DoX.Common
import Data.ByteString.Char8 ()
import Network.Socket hiding (recvBuf)
import Network.Socket.BufferPool (makeRecvN)
import Network.TLS (bye, contextNew, handshake)
import qualified UnliftIO.Exception as E

tlsResolver :: VCLimit -> Resolver
tlsResolver lim ri@ResolvInfo{..} q qctl = vcResolver "TLS" perform ri q qctl
  where
    -- Using a fresh connection
    perform solve = E.bracket open close $ \sock -> do
        E.bracket (contextNew sock params) bye $ \ctx -> do
            handshake ctx
            recvN <- makeRecvN "" $ recvTLS ctx
            let sendDoT = sendVC $ sendManyTLS ctx
                recvDoT = recvVC lim recvN
            solve sendDoT recvDoT

    open = openTCP rinfoHostName rinfoPortNumber
    params = getTLSParams rinfoHostName "dot" False
