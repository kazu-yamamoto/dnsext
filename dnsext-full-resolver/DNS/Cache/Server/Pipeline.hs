{-# LANGUAGE RecordWildCards #-}

module DNS.Cache.Server.Pipeline where

-- GHC packages
import Data.ByteString (ByteString)
import Data.IORef (atomicModifyIORef', newIORef, readIORef)

-- dnsext-* packages
import qualified DNS.Types as DNS
import qualified DNS.Types.Decode as DNS
import qualified DNS.Types.Encode as DNS

-- other packages
import qualified DNS.Log as Log

-- this package
import DNS.Cache.Iterative (CacheResult (..), Env (..), getResponseCached, getResponseIterative)

----------------------------------------------------------------

type Status = [(String, Int)]

----------------------------------------------------------------

data CntGet = CntGet
    { getHit' :: IO Int
    , getMiss' :: IO Int
    , getFailed' :: IO Int
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

----------------------------------------------------------------

cacherLogic
    :: Env
    -> CntInc
    -> (ByteString -> IO ())
    -> (DNS.DNSMessage -> IO ())
    -> ByteString
    -> IO ()
cacherLogic env CntInc{..} send toResolver req = do
    now <- currentSeconds_ env
    case DNS.decodeAt now req of
        Left e -> logLn Log.WARN $ "decode-error: " ++ show e
        Right reqMsg -> do
            mx <- getResponseCached env reqMsg
            case mx of
                None -> toResolver reqMsg
                Positive rspMsg -> do
                    incHit
                    send $ DNS.encode rspMsg
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
    -> DNS.DNSMessage
    -> IO ()
workerLogic env CntInc{..} send reqMsg = do
    ex <- getResponseIterative env reqMsg
    case ex of
        Right x -> do
            incMiss
            send $ DNS.encode x
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
    -> ByteString
    -> IO ()
cacheWorkerLogic env cntinc send req =
    cacherLogic env cntinc send (workerLogic env cntinc send) req
