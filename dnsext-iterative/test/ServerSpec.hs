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
    it "now" $ do
        let readableNow = pure (pure ())
        (vcs, _, _) <- initVcSession readableNow 100_000 50
        result <- timeout 3_000_000 $ waitVcInput vcs
        result `shouldBe` Just False
    it "wait" $ do
        let waitRead = do
                hasInput <- newTVarIO False
                let toReadable = writeTVar hasInput True
                toReadable `afterUSec` 100_000
                pure $ guard =<< readTVar hasInput
        (vcs, _, _) <- initVcSession waitRead 1_000_000 50
        result <- timeout 3_000_000 $ waitVcInput vcs
        result `shouldBe` Just False
    it "timeout" $ do
        let noReadable = pure retry
        (vcs, _, _) <- initVcSession noReadable 100_000 50
        result <- timeout 3_000_000 $ waitVcInput vcs
        result `shouldBe` Just True

waitOutputSpec :: Spec
waitOutputSpec = describe "server - wait VC output" $ do
    let noReadable = pure retry
    it "finish - timeout" $ do
        (vcs, _, _) <- initVcSession noReadable 100_000 50
        result <- timeout 3_000_000 $ waitVcOutput vcs
        result `shouldBe` Just (Just VfTimeout)
    it "finish - eof" $ do
        (vcs@VcSession{..}, _, _) <- initVcSession noReadable 1_000_000 50
        enableVcEof vcEof_ `afterUSec` 100_000
        result <- timeout 3_000_000 $ waitVcOutput vcs
        result `shouldBe` Just (Just VfEof)
    it "finish - eof supersede timeout" $ do
        (vcs@VcSession{..}, _, _) <- initVcSession noReadable 0 50
        atomically $ enableVcEof vcEof_
        result <- timeout 3_000_000 $ waitVcOutput vcs
        result `shouldBe` Just (Just VfEof)
    it "wait pendings" $ do
        (vcs@VcSession{..}, _, _) <- initVcSession noReadable 0 50
        let uid = 1
        atomically $ addVcPending vcPendings_ uid
        result <- timeout 100_000 $ waitVcOutput vcs
        result `shouldBe` Nothing {- expect outside timeout-}
    it "next" $ do
        (vcs, toSender, _) <- initVcSession noReadable 1_000_000 50
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
        m <- timeout 3_000_000 $ vcSession (pure $ pure ()) 5_000_000 ["6", "4", "2"]
        m `shouldBe` Just ((VfEof, VfEof), True)
    it "finish 2" $ do
        m <- timeout 3_000_000 $ vcSession (pure $ pure ()) 5_000_000 ["6", "4", "2", "6", "4", "2", "6", "4", "2"]
        m `shouldBe` Just ((VfEof, VfEof), True)
    it "timeout" $ do
        m <- timeout 3_000_000 $ vcSession (pure retry) 100_000 ["2"]
        m `shouldBe` Just ((VfTimeout, VfTimeout), False)
    it "wait slow" $ do
        m <- timeout 3_000_000 $ vcSession (pure $ pure ()) 50_000 ["10"]
        m `shouldBe` Just ((VfEof, VfEof), True)

---

{- FOUMOLU_DISABLE -}
vcSession :: IO (STM ()) -> Int -> [ByteString] -> IO ((VcFinished, VcFinished), Bool)
vcSession waitRead tmicro ws = do
    env <- newEmptyEnv
    (vcSess@VcSession{}, toSender, fromX) <- initVcSession waitRead tmicro 0
    toCacher <- getToCacher
    recv <- getRecv ws
    (getResult, send) <- getSend
    let myaddr = SockAddrInet 53 0x0100007f
        receiver = receiverVC "test-recv" env vcSess recv toCacher (mkInput myaddr toSender UDP)
        sender = senderVC "test-send" env vcSess send fromX
        debug = False
    when debug $ void $ forkIO $ replicateM_ 10 $ do
        {- dumper to debug -}
        dump vcSess
        threadDelay 500_000

    fstate <- TStat.concurrently "test-send" sender "test-recv" receiver
    let expect = sort ws
    result <- sort <$> getResult
    pure (fstate, result == expect)
{- FOUMOLU_ENABLE -}

dump :: VcSession -> IO ()
dump VcSession{..} = do
    (e, p, a) <- atomically $ (,,) <$> readTVar vcEof_ <*> readTVar vcPendings_ <*> vcRespAvail_
    putStrLn $ unwords ["eof:", show e, "pendings:", show p, "avail:", show a]

{- FOUMOLU_DISABLE -}
getToCacher :: IO (ToCacher -> IO ())
getToCacher = do
    mq <- newTQueueIO
    let bodyLoop = forever $ do
            Input{..} <- atomically (readTQueue mq)
            let intb = fromMaybe 0 $ readMaybe $ B8.unpack inputQuery
            threadDelay $ intb * 10_000
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
