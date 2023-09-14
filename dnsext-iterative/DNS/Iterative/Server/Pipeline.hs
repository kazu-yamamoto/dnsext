{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Server.Pipeline where

-- GHC packages
import Data.ByteString (ByteString)
import Data.IORef (atomicModifyIORef', newIORef, readIORef)

-- dnsext-* packages

import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.TAP.Schema as DNSTAP
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS

-- other packages
import qualified DNS.Log as Log
import Network.Socket (SockAddr)

-- this package
import DNS.Iterative.Internal (Env(..))
import DNS.Iterative.Query (CacheResult (..), getResponseCached, getResponseIterative)

----------------------------------------------------------------

data CntGet = CntGet
    { getHit :: IO Int
    , getMiss :: IO Int
    , getFailed :: IO Int
    }

data CntInc = CntInc
    { incHit :: IO ()
    , incMiss :: IO ()
    , incFailed :: IO ()
    }

newCounters :: IO (CntGet, CntInc)
newCounters = do
    (g0, i0) <- counter
    (g1, i1) <- counter
    (g2, i2) <- counter
    return (CntGet g0 g1 g2, CntInc i0 i1 i2)
  where
    counter :: IO (IO Int, IO ())
    counter = do
        ref <- newIORef 0
        return (readIORef ref, atomicModifyIORef' ref (\x -> (x + 1, ())))

readCounters :: CntGet -> IO [(String, Int)]
readCounters CntGet{..} = do
    hit <- getHit
    miss <- getMiss
    fail_ <- getFailed
    return
        [ ("hit", hit)
        , ("miss", miss)
        , ("fail", fail_)
        ]

----------------------------------------------------------------

cacherLogic
    :: Env
    -> CntInc
    -> (ByteString -> IO ())
    -> (DNS.EpochTime -> a -> Either DNS.DNSError DNS.DNSMessage)
    -> (DNS.DNSMessage -> IO ())
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> a
    -> IO ()
cacherLogic env CntInc{..} send decode toResolver proto mysa peersa req = do
    now <- currentSeconds_ env
    case decode now req of
        Left e -> logLn Log.WARN $ "decode-error: " ++ show e
        Right reqMsg -> do
            mx <- getResponseCached env reqMsg
            case mx of
                None -> toResolver reqMsg
                Positive rspMsg -> do
                    incHit
                    let bs = DNS.encode rspMsg
                    send bs
                    now' <- currentSeconds_ env
                    logDNSTAP_ env $ DNSTAP.composeMessage proto mysa peersa now' bs
                Negative replyErr -> do
                    incFailed
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
    -> CntInc
    -> (ByteString -> IO ())
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> DNS.DNSMessage
    -> IO ()
workerLogic env CntInc{..} send proto mysa peersa reqMsg = do
    ex <- getResponseIterative env reqMsg
    case ex of
        Right rspMsg -> do
            incMiss
            let bs = DNS.encode rspMsg
            send bs
            now' <- currentSeconds_ env
            logDNSTAP_ env $ DNSTAP.composeMessage proto mysa peersa now' bs
        Left e -> do
            incFailed
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
    -> CntInc
    -> (ByteString -> IO ())
    -> SocketProtocol
    -> SockAddr
    -> SockAddr
    -> [ByteString]
    -> IO ()
cacheWorkerLogic env cntinc send proto mysa peersa req = do
    let worker = workerLogic env cntinc send proto mysa peersa
    cacherLogic env cntinc send decode worker proto mysa peersa req
  where
    decode t bss = case DNS.decodeChunks t bss of
        Left e -> Left e
        Right (m, _) -> Right m