{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.TLS where

import Codec.Serialise
import DNS.Do53.Internal
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as BL
import qualified Network.HTTP2.TLS.Client as H2
import qualified Network.HTTP2.TLS.Internal as H2
import Network.Socket.BufferPool (makeRecvN)
import Network.TLS

tlsPersistentResolver :: PersistentResolver
tlsPersistentResolver ri@ResolveInfo{..} body =
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        recvN <- makeRecvN "" $ H2.recvTLS ctx
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit recvN
        vcPersistentResolver "TLS" sendDoT recvDoT ri body
  where
    settings = makeSettings ri

makeSettings :: ResolveInfo -> H2.Settings
makeSettings ResolveInfo{..} =
    H2.defaultSettings
        { H2.settingsValidateCert = False
        , H2.settingsWantSessionResume = case ractionResumptionInfo rinfoActions of
            Nothing -> Nothing
            Just r -> case deserialiseOrFail $ BL.fromStrict r of
                Left _ -> Nothing
                Right x -> Just x
        , H2.settingsUseEarlyData = ractionUseEarlyData rinfoActions
        , H2.settingsSessionManager =
            noSessionManager
                { sessionEstablish = \sid sd -> do
                    let bs = BL.toStrict $ serialise (sid, sd)
                    ractionSaveResumption rinfoActions bs
                    return Nothing
                }
        , H2.settingsKeyLogger = ractionKeyLog rinfoActions
        }

tlsResolver :: OneshotResolver
tlsResolver ri@ResolveInfo{..} q qctl =
    -- Using a fresh connection
    H2.runTLS settings (show rinfoIP) rinfoPort "dot" $ \ctx _ _ -> do
        recvN <- makeRecvN "" $ H2.recvTLS ctx
        let sendDoT = sendVC $ H2.sendManyTLS ctx
            recvDoT = recvVC rinfoVCLimit recvN
        vcResolver "TLS" sendDoT recvDoT ri q qctl
  where
    settings =
        H2.defaultSettings
            { H2.settingsValidateCert = False
            }
