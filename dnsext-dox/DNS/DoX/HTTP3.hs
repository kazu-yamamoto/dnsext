{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP3 where

import qualified Control.Exception as E
import DNS.Do53.Client
import DNS.Do53.Internal
import qualified Network.HTTP3.Client as H3
import qualified Network.QUIC.Client as QUIC

import DNS.DoX.HTTP2
import DNS.DoX.Imports
import DNS.DoX.QUIC

http3PersistentResolver :: PersistentResolver
http3PersistentResolver ri@ResolveInfo{..} body = QUIC.run cc $ \conn ->
    E.bracket H3.allocSimpleConfig H3.freeSimpleConfig $ \conf -> do
        ident <- ractionGenId rinfoActions
        H3.run conn cliconf conf $
            doHTTP tag ident ri body
        saveResumptionInfo conn ri tag
  where
    tag = nameTag ri "H3"
    cc = getQUICParams ri tag "h3" -- TLS SNI
    auth = fromMaybe (show rinfoIP) rinfoServerName
    cliconf =
        H3.defaultClientConfig
            { H3.scheme = "https"
            , H3.authority = auth -- HTTP :authority
            }

http3Resolver :: OneshotResolver
http3Resolver ri@ResolveInfo{..} q qctl = QUIC.run cc $ \conn ->
    E.bracket H3.allocSimpleConfig H3.freeSimpleConfig $ \conf -> do
        ident <- ractionGenId rinfoActions
        withTimeout ri $ do
            res <-
                H3.run conn cliconf conf $
                    doHTTPOneshot tag ident ri q qctl
            saveResumptionInfo conn ri tag
            return res
  where
    tag = nameTag ri "H3"
    cc = getQUICParams ri tag "h3" -- TLS SNI
    auth = fromMaybe (show rinfoIP) rinfoServerName
    cliconf =
        H3.defaultClientConfig
            { H3.scheme = "https"
            , H3.authority = auth -- HTTP :authority
            }
