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

record
    :: Env
    -> DNS.DNSMessage
    -> DNS.DNSMessage
    -> ByteString
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> IO ()
record env reqMsg rspMsg rspWire proto mysa peersa = do
    (s, ns) <- getCurrentTimeNsec
    logDNSTAP_ env $ DNSTAP.composeMessage proto mysa peersa s ns rspWire
    let st = stats_ env
        DNS.Question{..} = head $ DNS.question reqMsg
        DNS.DNSFlags{..} = DNS.flags reqMsg
    incStatsM st fromQueryTypes qtype (Just QueryTypeOther)
    incStatsM st fromDNSClass qclass (Just DNSClassOther)
    let rc = DNS.rcode rspMsg
    incStatsM st fromRcode rc Nothing
    when (rc == DNS.NoErr) $
        if DNS.answer rspMsg == []
            then incStats st RcodeNoData
            else incStats st RcodeNoError
    when authAnswer $ incStats st FlagAA
    when authenData $ incStats st FlagAD
    when chkDisable $ incStats st FlagCD
    when isResponse $ incStats st FlagQR
    when recAvailable $ incStats st FlagRA
    when recDesired $ incStats st FlagRD
    when trunCation $ incStats st FlagTC

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
        Left e -> logLn env Log.WARN $ "decode-error: " ++ show e
        Right reqMsg -> do
            mx <- getResponseCached env reqMsg
            case mx of
                None -> toResolver reqMsg
                Positive rspMsg -> do
                    incStats (stats_ env) CacheHit
                    let bs = DNS.encode rspMsg
                    send bs
                    record env reqMsg rspMsg bs proto mysa peersa
                Negative replyErr ->
                    cacheFailed env send proto mysa peersa reqMsg replyErr

logLn :: Env -> Log.Level -> String -> IO ()
logLn env level = logLines_ env level Nothing . (: [])

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
            record env reqMsg rspMsg bs proto mysa peersa
        Left e -> cacheFailed env send proto mysa peersa reqMsg e

----------------------------------------------------------------

cacheFailed
    :: Env
    -> (ByteString -> IO ())
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> DNS.DNSMessage
    -> String
    -> IO ()
cacheFailed env send proto mysa peersa reqMsg emsg = do
    incStats (stats_ env) CacheFailed
    let rspMsg = reqMsg{DNS.flags = (DNS.flags reqMsg){DNS.isResponse = True}, DNS.rcode = DNS.FormatErr}
        bs = DNS.encode rspMsg
    send bs
    record env reqMsg rspMsg bs proto mysa peersa
    logLn env Log.WARN $
        "cached: response cannot be generated: "
            ++ emsg
            ++ ": "
            ++ show (DNS.question reqMsg)

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
    cacherLogic env send DNS.decodeChunks worker proto mysa peersa req
