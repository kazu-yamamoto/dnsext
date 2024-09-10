{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module ServerSpec where

import Test.Hspec

--
import Control.Concurrent
import Control.Concurrent.STM
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B8
import Data.Functor
import Data.IORef
import Data.List
import Data.Maybe
import System.Environment (lookupEnv)
import System.Timeout (timeout)
import Text.Read (readMaybe)

--
import DNS.TAP.Schema (SocketProtocol (..))
import qualified DNS.ThreadStats as TStat

--
import DNS.Iterative.Server

spec :: Spec
spec = do
    waitInputSpec
    waitOutputSpec
    sessionSpec

waitInputSpec :: Spec
waitInputSpec = describe "server - wait VC input" $ do
    it "now" $ withVcSession readableNow 100_000 50 $ \(vcs, _, _) -> do
        result <- timeout 3_000_000 $ waitVcInput vcs
        result `shouldBe` Just False
    it "wait" $ withVcSession waitRead 1_000_000 50 $ \(vcs, _, _) -> do
        result <- timeout 3_000_000 $ waitVcInput vcs
        result `shouldBe` Just False
    it "timeout" $ withVcSession noReadable 100_000 50 $ \(vcs, _, _) -> do
        result <- timeout 3_000_000 $ waitVcInput vcs
        result `shouldBe` Just True
  where
    readableNow = pure (pure ())
    waitRead = do
        hasInput <- newTVarIO False
        let toReadable = writeTVar hasInput True
        toReadable `afterUSec` 100_000
        pure $ guard =<< readTVar hasInput
    noReadable = pure retry

waitOutputSpec :: Spec
waitOutputSpec = describe "server - wait VC output" $ do
    let noReadable = pure retry
    it "finish - timeout" $ withVcSession noReadable 100_000 50 $ \(vcs, _, _) -> do
        result <- timeout 3_000_000 $ waitVcOutput vcs
        result `shouldBe` Just (Just VfTimeout)
    it "finish - eof" $ withVcSession noReadable 1_000_000 50 $ \(vcs@VcSession{..}, _, _) -> do
        enableVcEof vcEof_ `afterUSec` 100_000
        result <- timeout 3_000_000 $ waitVcOutput vcs
        result `shouldBe` Just (Just VfEof)
    it "finish - eof supersede timeout" $ withVcSession noReadable 0 50 $ \(vcs@VcSession{..}, _, _) -> do
        atomically $ enableVcEof vcEof_
        result <- timeout 3_000_000 $ waitVcOutput vcs
        result `shouldBe` Just (Just VfEof)
    it "wait pendings" $ withVcSession noReadable 0 50 $ \(vcs@VcSession{..}, _, _) -> do
        let uid = 1
        atomically $ addVcPending vcPendings_ uid
        result <- timeout 100_000 $ waitVcOutput vcs
        result `shouldBe` Nothing {- expect outside timeout-}
    it "next" $ withVcSession noReadable 1_000_000 50 $ \(vcs, toSender, _) -> do
        _ <- forkIO $ threadDelay 100_000 >> toSender (Output "hello" 1 {- dummy -} dummyPeer)
        result <- timeout 3_000_000 $ waitVcOutput vcs
        result `shouldBe` Just Nothing

afterUSec :: STM () -> Int -> IO ()
afterUSec stm delay = void $ forkIO $ do
    threadDelay delay
    atomically stm

sessionSpec :: Spec
sessionSpec = describe "server - VC session" $ do
    it "finish 1" $ do
        m <- timeout 3_000_000 $ vcSession (pure $ pure ()) 5_000_000 ["60", "40", "20"]
        m `shouldBe` Just ((VfEof, VfEof), True)
    it "finish 2" $ do
        m <- timeout 3_000_000 $ vcSession (pure $ pure ()) 5_000_000 ["60", "40", "20", "60", "40", "20", "60", "40", "20"]
        m `shouldBe` Just ((VfEof, VfEof), True)
    it "timeout" $ do
        m <- timeout 3_000_000 $ vcSession (pure retry) 100_000 ["20"]
        m `shouldBe` Just ((VfTimeout, VfTimeout), False)
    it "wait slow" $ do
        m <- timeout 3_000_000 $ vcSession (pure $ pure ()) 50_000 ["100"]
        m `shouldBe` Just ((VfEof, VfEof), True)

vcSession :: IO (STM ()) -> Int -> [ByteString] -> IO ((VcFinished, VcFinished), Bool)
vcSession waitRead tmicro ws = do
    recv <- getRecv ws
    (fstate, result) <- runSession 1000 recv waitRead tmicro
    let expect = sort ws
    pure (fstate, result == expect)

---

{- FOUMOLU_DISABLE -}
runSession :: Int -> IO (ByteString, PeerInfo) -> IO (STM ()) -> Int -> IO ((VcFinished, VcFinished), [ByteString])
runSession factor recv waitRead tmicro = withVcSession waitRead tmicro 0 $ \(vcSess@VcSession{}, toSender, fromX) -> do
    env <- newEmptyEnv
    toCacher <- getToCacher factor
    (getResult, send) <- getSend
    debug <- maybe False ((== "1") . take 1) <$> lookupEnv "VCTEST_DEBUG"
    let myaddr = SockAddrInet 53 0x0100007f
        receiver = receiverVC "test-recv" env vcSess recv toCacher (mkInput myaddr toSender UDP)
        sender = senderVC "test-send" env vcSess send fromX
    when debug $ void $ forkIO $ replicateM_ 10 $ do
        {- dumper to debug -}
        dump vcSess
        threadDelay 500_000

    fstate <- TStat.concurrently "test-send" sender "test-recv" receiver
    result <- sort <$> getResult
    pure (fstate, result)
{- FOUMOLU_ENABLE -}

dump :: VcSession -> IO ()
dump VcSession{..} = do
    (e, p, a) <- atomically $ (,,) <$> readTVar vcEof_ <*> readTVar vcPendings_ <*> vcRespAvail_
    putStrLn $ unwords ["eof:", show e, "pendings:", show p, "avail:", show a]

{- FOUMOLU_DISABLE -}
getToCacher :: Int -> IO (ToCacher -> IO ())
getToCacher factor = do
    mq <- newTQueueIO
    let bodyLoop = forever $ do
            Input{..} <- atomically (readTQueue mq)
            let intb = fromMaybe 0 $ readMaybe $ B8.unpack inputQuery
            threadDelay $ intb * factor
            inputToSender $ Output inputQuery inputRequestNum inputPeerInfo
    _ <- replicateM 4 (forkIO bodyLoop)
    pure (atomically . writeTQueue mq)
{- FOUMOLU_ENABLE -}

getRecv :: [ByteString] -> IO Recv
getRecv ws = do
    ref <- newIORef ws
    pure $ rstep ref
  where
    rstep ref = do
        s <- readIORef ref
        case s of
            [] -> pure (mempty, dummyPeer)
            c : cs -> writeIORef ref cs $> (c, dummyPeer)

getSend :: IO (IO [ByteString], Send)
getSend = do
    ref <- newIORef []
    pure (readIORef ref, \x _ -> sstep ref x)
  where
    ins x s = (x : s, ())
    sstep ref x = atomicModifyIORef' ref (ins x)

dummyPeer :: PeerInfo
dummyPeer = PeerInfoVC $ SockAddrInet 12345 0x0100007f
