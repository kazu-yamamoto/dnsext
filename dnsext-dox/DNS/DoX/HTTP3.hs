{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP3 where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.Types
import qualified Data.ByteString.Char8 as C8
import Network.HTTP3.Client
import Network.QUIC
import qualified Network.QUIC.Client as QUIC
import qualified UnliftIO.Exception as E

import DNS.DoX.Common
import DNS.DoX.HTTP2

http3Resolver :: Resolver
http3Resolver ri@ResolvInfo{..} q qctl = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        ident <- ractionGenId rinfoActions
        h3resolver conn conf ident ri q qctl
  where
    cc = getQUICParams rinfoHostName rinfoPortNumber "h3"

h3resolver :: Connection -> Config -> Identifier -> Resolver
h3resolver conn conf ident ri@ResolvInfo{..} q qctl =
    run conn cliconf conf $ doHTTP ri q qctl ident
  where
    cliconf = ClientConfig {
        scheme = "https"
      , authority = C8.pack rinfoHostName
      }
