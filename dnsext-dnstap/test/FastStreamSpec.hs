{-# LANGUAGE OverloadedStrings #-}

module FastStreamSpec where

import DNS.TAP.FastStream
import Data.ByteString ()
import Data.IORef
import Network.Run.TCP
import Test.Hspec
import UnliftIO.Concurrent
import qualified UnliftIO.Exception as E

spec :: Spec
spec = do
    describe "reader & writer" $ do
        it "can send stream correctly in uni-directional" $ do
            let conf = Config False False
            readWrite conf
        it "can send stream correctly in bi-directional" $ do
            let conf = Config True False
            readWrite conf

readWrite :: Config -> IO ()
readWrite conf = do
    mvar <- newEmptyMVar
    E.bracket (forkIO $ server mvar ) killThread $ \_ -> client mvar
  where
    n = 10 :: Int
    client mvar = do
        threadDelay 10000
        runTCPClient "127.0.0.1" "50002" $ \sock -> do
            ctx <- newWriterContext sock conf
            ref <- newIORef 0
            writer ctx $ do
                i <- readIORef ref
                if i < n
                    then do
                      let i' = i + 1
                      writeIORef ref i'
                      return "foo!"
                    else return ""
            takeMVar mvar `shouldReturn` ()
    server mvar = runTCPServer (Just "127.0.0.1") "50002" $ \sock -> do
        ctx <- newReaderContext sock conf
        ref <- newIORef 0
        reader ctx $ \_ -> modifyIORef' ref (+1)
        readIORef ref `shouldReturn` n
        putMVar mvar ()
