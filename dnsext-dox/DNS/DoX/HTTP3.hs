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
        ident <- ractionGenId rinfoActions
        run conn cliconf conf $
            doHTTP tag ident ri body
        saveResumptionInfo conn ri tag
  where
    tag = nameTag ri "H3"
    cc = getQUICParams ri tag "h3"
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = show rinfoIP
            }

http3Resolver :: OneshotResolver
http3Resolver ri@ResolveInfo{..} q qctl = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        ident <- ractionGenId rinfoActions
        withTimeout ri $ do
            res <-
                run conn cliconf conf $
                    doHTTPOneshot tag ident ri q qctl
            saveResumptionInfo conn ri tag
            return res
  where
    tag = nameTag ri "H3"
    cc = getQUICParams ri tag "h3"
    cliconf =
        ClientConfig
            { scheme = "https"
            , authority = show rinfoIP
            }
