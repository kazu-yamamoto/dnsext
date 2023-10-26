{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.HTTP3 where

-- GHC packages

import Data.ByteString.Char8 ()

-- dnsext-* packages

-- other packages
import qualified Network.HTTP3.Server as H3
import qualified Network.QUIC.Server as QUIC
import Network.TLS (Credentials (..))
import qualified System.TimeManager as T

-- this package
import DNS.Iterative.Server.HTTP2
import DNS.Iterative.Server.QUIC
import DNS.Iterative.Server.Types

----------------------------------------------------------------
http3Server :: Credentials -> VcServerConfig -> Server
http3Server creds VcServerConfig{..} env toCacher port host = do
    let http3server = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            QUIC.run sconf $ \conn ->
                H3.run conn (conf mgr) $ doHTTP env toCacher
    return [http3server]
  where
    sconf = getServerConfig creds host port "h3"
    conf mgr =
        H3.Config
            { confHooks = H3.defaultHooks
            , confTimeoutManager = mgr
            , confPositionReadMaker = H3.defaultPositionReadMaker
            }
