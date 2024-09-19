{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.TCP (
    tcpServers,
)
where

-- GHC packages
import Control.Concurrent.STM (atomically)
import qualified Data.ByteString as BS
import Data.Functor

-- dnsext-* packages
import qualified DNS.Do53.Internal as DNS
import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

-- other packages
import Network.Run.TCP
import Network.Socket (getPeerName, getSocketName, waitReadSocketSTM)

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server.Pipeline
import DNS.Iterative.Server.Types
import DNS.Iterative.Stats (incStatsTCP53, sessionStatsTCP53)

----------------------------------------------------------------

tcpServers :: VcServerConfig -> ServerActions
tcpServers conf env toCacher ss =
    concat <$> mapM (tcpServer conf env toCacher) ss

tcpServer :: VcServerConfig -> Env -> (ToCacher -> IO ()) -> Socket -> IO ([IO ()])
tcpServer VcServerConfig{..} env toCacher s = do
    name <- socketName s <&> (++ "/tcp")
    let tcpserver =
            withLocationIOE name $
                runTCPServerWithSocket s go
    return ([tcpserver])
  where
    maxSize = fromIntegral vc_query_max_size
    tmicro = vc_idle_timeout * 1_000_000
    go sock = sessionStatsTCP53 (stats_ env) $ do
        mysa <- getSocketName sock
        peersa <- getPeerName sock
        logLn env Log.DEBUG $ "tcp-srv: accept: " ++ show peersa
        let peerInfo = PeerInfoVC peersa
        (vcSess, toSender, fromX) <- initVcSession (waitReadSocketSTM sock) vc_slowloris_size
        withVcTimer tmicro (atomically $ enableVcTimeout $ vcTimeout_ vcSess) $ \vcTimer -> do
            let recv = getRecvVC vc_slowloris_size vcTimer $ do
                    (siz, bss) <- DNS.recvVC maxSize $ DNS.recvTCP sock
                    if siz == 0
                        then return ("", peerInfo)
                        else incStatsTCP53 peersa (stats_ env) $> (BS.concat bss, peerInfo)
                send = getSendVC vcTimer $ \bs _ -> DNS.sendVC (DNS.sendTCP sock) bs
                receiver = receiverVC "tcp-recv" env vcSess vcTimer recv toCacher $ mkInput mysa toSender TCP
                sender = senderVC "tcp-send" env vcSess vcTimer send fromX
            TStat.concurrently_ "tcp-send" sender "tcp-recv" receiver
        logLn env Log.DEBUG $ "tcp-srv: close: " ++ show peersa
