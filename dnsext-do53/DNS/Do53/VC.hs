{-# LANGUAGE RecordWildCards #-}

module DNS.Do53.VC (
    withVCResolver,
    withTCPResolver,
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

-- import System.IO.Error (annotateIOError)
-- import qualified DNS.Log as Log

import DNS.Do53.Do53 hiding (vcResolver)
import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Query
import DNS.Do53.Types
import DNS.Types
import DNS.Types.Decode

type VCResolver = Question -> QueryControls -> IO (Either DNSError Reply)

withTCPResolver
    :: VCLimit
    -> ResolveInfo
    -> (VCResolver -> IO ())
    -> IO ()
withTCPResolver lim ResolveInfo{..} body = E.bracket open close $ \sock -> do
    let send = sendVC $ sendTCP sock
        recv = recvVC lim $ recvTCP sock
    withVCResolver send recv rinfoActions body
  where
    open = openTCP rinfoIP rinfoPort

withVCResolver
    :: Send
    -> RecvMany
    -> ResolveActions
    -> (VCResolver -> IO ())
    -> IO ()
withVCResolver send recv ResolveActions{..} body = do
    inpQ <- newTQueueIO
    ref <- newIORef emp
    race_
        (concurrently_ (sender inpQ) (recver ref))
        (body $ resolve inpQ ref)
  where
    emp = IM.empty :: IntMap (MVar Reply)
    resolve inpQ ref q qctl = do
        ident <- ractionGenId
        var <- newEmptyMVar :: IO (MVar Reply)
        let key = fromIntegral ident
            qry = encodeQuery ident q qctl
            tx = BS.length qry
        atomicModifyIORef' ref (\m -> (IM.insert key var m, ()))
        atomically $ writeTQueue inpQ qry
        mres <- ractionTimeout $ takeMVar var
        return $ case mres of
            Nothing -> Left TimeoutExpired
            Just (Reply msg _ rx) -> case checkRespM q ident msg of
                Nothing -> Right $ Reply msg tx rx
                Just err -> Left err

    sender inpQ = forever (atomically (readTQueue inpQ) >>= send)

    del idnt m = swap $ IM.updateLookupWithKey (\_ _ -> Nothing) idnt m

    recver ref = forever $ do
        -- fixme
        (rx, bss) <- recv -- `E.catch` ioErrorToDNSError q ri proto
        now <- ractionGetTime
        case decodeChunks now bss of
            Left _e -> return () -- fixme
            Right msg -> do
                let key = fromIntegral $ identifier msg
                Just var <- atomicModifyIORef' ref $ del key
                putMVar var $ Reply msg 0 {- dummy -} rx
