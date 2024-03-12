{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP3 where

import DNS.Do53.Client
import DNS.Do53.Internal
import Network.HTTP3.Client
import qualified Network.QUIC.Client as QUIC
import qualified UnliftIO.Exception as E

import DNS.DoX.HTTP2
import DNS.DoX.Imports
import DNS.DoX.QUIC

withHttp3Resolver :: ShortByteString -> PipelineResolver
withHttp3Resolver path ri@ResolveInfo{..} body = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        let proto = "H3"
        ident <- ractionGenId rinfoActions
        run conn cliconf conf $
            doHTTP proto ident path ri body
  where
    cc = getQUICParams rinfoIP rinfoPort "h3"
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = show rinfoIP
            }

http3Resolver :: ShortByteString -> OneshotResolver
http3Resolver path ri@ResolveInfo{..} q qctl = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        let proto = "H3"
        ident <- ractionGenId rinfoActions
        withTimeout ri $
            run conn cliconf conf $
                doHTTPOneshot proto ident path ri q qctl
  where
    cc = getQUICParams rinfoIP rinfoPort "h3"
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = show rinfoIP
            }
