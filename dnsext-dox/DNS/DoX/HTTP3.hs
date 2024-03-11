{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP3 where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.Types
import Network.HTTP3.Client
import Network.QUIC
import qualified Network.QUIC.Client as QUIC
import qualified UnliftIO.Exception as E

import DNS.DoX.HTTP2
import DNS.DoX.Imports
import DNS.DoX.QUIC

http3Resolver :: ShortByteString -> OneshotResolver
http3Resolver path ri@ResolveInfo{..} q qctl = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        ident <- ractionGenId rinfoActions
        h3resolver conn conf ident path ri q qctl
  where
    cc = getQUICParams rinfoIP rinfoPort "h3"

h3resolver
    :: Connection -> Config -> Identifier -> ShortByteString -> OneshotResolver
h3resolver conn conf ident path ri@ResolveInfo{..} q qctl = do
    let proto = "H3"
    withTimeout ri proto $
        run conn cliconf conf $
            doHTTP proto ident path ri q qctl
  where
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = show rinfoIP
            }
