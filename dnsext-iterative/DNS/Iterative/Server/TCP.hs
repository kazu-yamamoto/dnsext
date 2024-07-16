{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TCP where

-- GHC packages
import Control.Monad (when)
import Data.Functor
import qualified Data.ByteString as BS

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import Network.Run.TCP

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsTCP53, sessionStatsTCP53)

----------------------------------------------------------------

tcpServer :: VcServerConfig -> Server
tcpServer VcServerConfig{..} env toCacher port host = do
    let tcpserver = withLoc $ runTCPServer (Just host) (show port) $ go
    return ([tcpserver])
  where
    tmicro = vc_idle_timeout * 1_000_000
    withLoc = withLocationIOE (show host ++ ":" ++ show port ++ "/tcp")
    maxSize = fromIntegral vc_query_max_size
    go sock = sessionStatsTCP53 (stats_ env) $ do
        mysa <- getSocketName sock
        peersa <- getPeerName sock
        logLn env Log.DEBUG $ "tcp-srv: accept: " ++ show peersa
        let peerInfo = PeerInfoVC peersa
        (vcSess@VcSession{..}, toSender, fromX) <- initVcSession (waitReadSocketSTM' sock) tmicro
        let recv = do
                (siz, bss) <- DNS.recvVC maxSize $ DNS.recvTCP sock
                if siz == 0
                    then updateVcTimeout tmicro vcTimeout_ $> ("", peerInfo)
                    else do
                        when (siz > vc_slowloris_size) $ updateVcTimeout tmicro vcTimeout_
                        incStatsTCP53 peersa (stats_ env)
                        return (BS.concat bss, peerInfo)
            send bs _ = do
                DNS.sendVC (DNS.sendTCP sock) bs
                updateVcTimeout tmicro vcTimeout_
            receiver = receiverVC "tcp-recv" env vcSess recv toCacher $ mkInput mysa toSender TCP
            sender = senderVC "tcp-send" env vcSess send fromX
        TStat.concurrently_ "tcp-send" sender "tcp-recv" receiver
        logLn env Log.DEBUG $ "tcp-srv: close: " ++ show peersa
