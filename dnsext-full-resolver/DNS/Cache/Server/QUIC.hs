{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.QUIC where

-- GHC packages
import Control.Concurrent (forkFinally)
import Control.Monad (forever, void, when)
import Data.ByteString (ByteString)
import Data.ByteString.Char8 ()

-- dnsext-* packages
import DNS.TAP.Schema (SocketProtocol (..))

-- other packages
import qualified DNS.Do53.Internal as DNS
import qualified Network.QUIC as QUIC
import Network.QUIC.Server (ServerConfig (..))
import qualified Network.QUIC.Server as QUIC
import Network.TLS (Credentials (..))
import qualified System.TimeManager as T

-- this package
import DNS.Cache.Server.Pipeline
import DNS.Cache.Server.Types

----------------------------------------------------------------
quicServer :: Credentials -> VcServerConfig -> Server
quicServer creds VcServerConfig{..} env port host = do
    (cntget, cntinc) <- newCounters
    let quicserver = T.withManager (vc_idle_timeout * 1000000) $ \mgr ->
            QUIC.run sconf $ \conn -> do
                info <- QUIC.getConnectionInfo conn
                let mysa = QUIC.localSockAddr info
                    peersa = QUIC.remoteSockAddr info
                forever $ do
                    strm <- QUIC.acceptStream conn
                    let server = do
                            th <- T.registerKillThread mgr $ return ()
                            let send bs = do
                                    DNS.sendVC (QUIC.sendStreamMany strm) bs
                                    QUIC.shutdownStream strm
                                    T.tickle th
                                recv = do
                                    bss@(siz, _) <- DNS.recvVC maxSize $ QUIC.recvStream strm
                                    when (siz > vc_slowloris_size) $ T.tickle th
                                    return bss
                            (_n, bss) <- recv
                            cacheWorkerLogic env cntinc send DOQ mysa peersa bss
                    void $ forkFinally server (\_ -> QUIC.closeStream strm)
    return ([quicserver], [readCounters cntget])
  where
    sconf = getServerConfig creds host port "doq"
    maxSize = fromIntegral vc_query_max_size

getServerConfig :: Credentials -> String -> PortNumber -> ByteString -> ServerConfig
getServerConfig creds host port alpn =
    QUIC.defaultServerConfig
        { scAddresses = [(read host, port)]
        , scALPN = Just (\_ bss -> if alpn `elem` bss then return alpn else return "")
        , scCredentials = creds
        }
