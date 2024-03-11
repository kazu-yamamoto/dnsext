{-# LANGUAGE RecordWildCards #-}

module DNS.Do53.VC (
    withVCResolver,
    withTCPResolver,
    PipelineResolver,
) where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Concurrent.STM
import qualified Control.Exception as E
import qualified Data.ByteString as BS
import Data.IORef
import Data.IntMap (IntMap)
import qualified Data.IntMap as IM
import Data.Tuple (swap)
import Network.Socket
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

-- import System.IO.Error (annotateIOError)
-- import qualified DNS.Log as Log

import DNS.Do53.Do53 hiding (vcResolver)
import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Query
import DNS.Do53.Types
import DNS.Types
import DNS.Types.Decode

type RVar = MVar (Either DNSError Reply)
type PipelineResolver = VCLimit -> ResolveInfo -> (Resolver -> IO ()) -> IO ()

withTCPResolver :: PipelineResolver
withTCPResolver lim ri@ResolveInfo{..} body = E.bracket open close $ \sock -> do
    let send = sendVC $ sendTCP sock
        recv = recvVC lim $ recvTCP sock
    withVCResolver "TCP" send recv ri body
  where
    open = openTCP rinfoIP rinfoPort

withVCResolver
    :: String
    -> Send
    -> RecvMany
    -> ResolveInfo
    -> (Resolver -> IO ())
    -> IO ()
withVCResolver proto send recv ri@ResolveInfo{..} body = do
    inpQ <- newTQueueIO
    ref <- newIORef emp
    race_
        (concurrently_ (sender inpQ) (recver ref))
        (body $ resolve inpQ ref)
  where
    emp = IM.empty :: IntMap RVar
    resolve inpQ ref q qctl = do
        ident <- ractionGenId rinfoActions
        var <- newEmptyMVar :: IO RVar
        let key = fromIntegral ident
            qry = encodeQuery ident q qctl
            tx = BS.length qry
        atomicModifyIORef' ref (\m -> (IM.insert key var m, ()))
        atomically $ writeTQueue inpQ qry
        mres <- timeout (ractionTimeoutTime rinfoActions) $ takeMVar var
        return $ case mres of
            Nothing -> Left TimeoutExpired
            Just (Left e) -> Left e
            Just (Right (Reply msg _ rx)) -> case checkRespM q ident msg of
                Nothing -> Right $ toResult ri proto $ Reply msg tx rx
                Just err -> Left err

    sender inpQ = forever (atomically (readTQueue inpQ) >>= send)

    del idnt m = swap $ IM.updateLookupWithKey (\_ _ -> Nothing) idnt m

    recver ref = forever $ do
        (rx, bss) <-
            recv `E.catch` \ne -> do
                let e = ioErrorToDNSError ri proto ne
                cleanup ref e
                E.throwIO e
        now <- ractionGetTime rinfoActions
        case decodeChunks now bss of
            Left e -> do
                cleanup ref e
                E.throwIO e
            Right msg -> do
                let key = fromIntegral $ identifier msg
                Just var <- atomicModifyIORef' ref $ del key
                putMVar var $ Right $ Reply msg 0 {- dummy -} rx

    cleanup ref e = do
        vars <- IM.elems <$> readIORef ref
        mapM_ (\var -> putMVar var (Left e)) vars

ioErrorToDNSError :: ResolveInfo -> String -> IOError -> DNSError
ioErrorToDNSError ResolveInfo{..} protoName ioe = NetworkFailure aioe
  where
    loc = protoName ++ show rinfoPort ++ "@" ++ show rinfoIP
    aioe = annotateIOError ioe loc Nothing Nothing
