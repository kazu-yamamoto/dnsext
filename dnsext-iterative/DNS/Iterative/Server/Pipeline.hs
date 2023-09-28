{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.Pipeline where

-- GHC packages
import Data.ByteString (ByteString)

-- dnsext-* packages

import qualified DNS.Log as Log
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.TAP.Schema as DNSTAP
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS
import DNS.Types.Time

-- other packages
import Control.Monad (when)
import Network.Socket (SockAddr)

-- this package
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Query (CacheResult (..), getResponseCached, getResponseIterative)
import DNS.Iterative.Stats

----------------------------------------------------------------

cacherLogic
    :: Env
    -> (ByteString -> IO ())
    -> (EpochTime -> a -> Either DNS.DNSError DNS.DNSMessage)
    -> (DNS.DNSMessage -> IO ())
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> a
    -> IO ()
cacherLogic env send decode toResolver proto mysa peersa req = do
    now <- currentSeconds_ env
    case decode now req of
        Left e -> logLn Log.WARN $ "decode-error: " ++ show e
        Right reqMsg -> do
            mx <- getResponseCached env reqMsg
            case mx of
                None -> toResolver reqMsg
                Positive rspMsg -> do
                    incStats (stats_ env) CacheHit
                    let bs = DNS.encode rspMsg
                    send bs
                    (s,ns) <- getCurrentTimeNsec
                    let st = stats_ env
                        DNS.Question{..} = head $ DNS.question reqMsg
                        DNS.DNSFlags{..} = DNS.flags $ DNS.header reqMsg
                    incStatsM st fromQueryTypes qtype (Just QueryTypeOther)
                    incStatsM st fromDNSClass qclass (Just DNSClassOther)
                    when authAnswer $ incStats st FlagAA
                    when authenData $ incStats st FlagAD
                    when chkDisable $ incStats st FlagCD
                    when (qOrR == DNS.QR_Response) $ incStats st FlagQR
                    when recAvailable $ incStats st FlagRA
                    when recDesired $ incStats st FlagRD
                    when trunCation $ incStats st FlagTC
                    logDNSTAP_ env $ DNSTAP.composeMessage proto mysa peersa s ns bs
                Negative replyErr -> do
                    incStats (stats_ env) CacheFailed
                    logLn Log.WARN $
                        "cached: response cannot be generated: "
                            ++ replyErr
                            ++ ": "
                            ++ show (DNS.question reqMsg)
  where
    logLn level = logLines_ env level Nothing . (: [])

----------------------------------------------------------------

workerLogic
    :: Env
    -> (ByteString -> IO ())
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> DNS.DNSMessage
    -> IO ()
workerLogic env send proto mysa peersa reqMsg = do
    ex <- getResponseIterative env reqMsg
    case ex of
        Right rspMsg -> do
            incStats (stats_ env) CacheMiss
            let bs = DNS.encode rspMsg
            send bs
            (s,ns) <- getCurrentTimeNsec
            let st = stats_ env
                DNS.Question{..} = head $ DNS.question reqMsg
                DNS.DNSFlags{..} = DNS.flags $ DNS.header reqMsg
            incStatsM st fromQueryTypes qtype (Just QueryTypeOther)
            incStatsM st fromDNSClass qclass (Just DNSClassOther)
            when authAnswer $ incStats st FlagAA
            when authenData $ incStats st FlagAD
            when chkDisable $ incStats st FlagCD
            when (qOrR == DNS.QR_Response) $ incStats st FlagQR
            when recAvailable $ incStats st FlagRA
            when recDesired $ incStats st FlagRD
            when trunCation $ incStats st FlagTC
            logDNSTAP_ env $ DNSTAP.composeMessage proto mysa peersa s ns bs
        Left e -> do
            incStats (stats_ env) CacheFailed
            logLn Log.WARN $
                "resolv: response cannot be generated: "
                    ++ e
                    ++ ": "
                    ++ show (DNS.question reqMsg)
  where
    logLn level = logLines_ env level Nothing . (: [])

----------------------------------------------------------------

cacheWorkerLogic
    :: Env
    -> (ByteString -> IO ())
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> [ByteString]
    -> IO ()
cacheWorkerLogic env send proto mysa peersa req = do
    let worker = workerLogic env send proto mysa peersa
    cacherLogic env send decode worker proto mysa peersa req
  where
    decode t bss = case DNS.decodeChunks t bss of
        Left e -> Left e
        Right (m, _) -> Right m
