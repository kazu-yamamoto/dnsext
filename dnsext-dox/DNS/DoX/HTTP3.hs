{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP3 where

import DNS.Do53.Client
import DNS.Do53.Internal
import Network.HTTP3.Client
import qualified Network.QUIC.Client as QUIC
import qualified UnliftIO.Exception as E

import DNS.DoX.HTTP2
import DNS.DoX.QUIC

http3PersistentResolver :: PersistentResolver
http3PersistentResolver ri@ResolveInfo{..} body = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        let proto = "H3"
        ident <- ractionGenId rinfoActions
        run conn cliconf conf $
            doHTTP proto ident ri body
  where
    cc = getQUICParams rinfoIP rinfoPort "h3"
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = show rinfoIP
            }

http3Resolver :: OneshotResolver
http3Resolver ri@ResolveInfo{..} q qctl = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        let proto = "H3"
        ident <- ractionGenId rinfoActions
        withTimeout ri $
            run conn cliconf conf $
                doHTTPOneshot proto ident ri q qctl
  where
    cc = getQUICParams rinfoIP rinfoPort "h3"
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = show rinfoIP
            }
