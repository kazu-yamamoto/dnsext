module DNS.ThreadStats where

import GHC.Conc.Sync (listThreads, labelThread, threadLabel, threadStatus)
import Control.Concurrent
import Control.Concurrent.Async (Async, asyncThreadId)
import qualified Control.Concurrent.Async as Async
import Control.Monad
import Data.Functor
import Data.List
import Data.Maybe

showTid :: ThreadId -> String
showTid tid = stripTh $ show tid
  where
    stripTh x = fromMaybe x $ stripPrefix "ThreadId " x

getThreadLabel :: IO String
getThreadLabel = withName (pure "<no-label>") $ \tid n -> pure $ n ++ ": " ++ showTid tid
  where
    withName nothing just = do
        tid <- myThreadId
        maybe nothing (just tid) =<< threadLabel tid

dumpThreads :: IO [String]
dumpThreads = do
    ts <- mapM getName =<< listThreads
    vs <- sequence [ dump tid n | (tid, Just n)  <- ts ]
    pure . map (uncurry (++)) $ sort vs
  where
    getName tid = (,) tid <$> threadLabel tid
    dump tid name = do
        st <- show <$> threadStatus tid
        let stid = showTid tid
            pad = replicate (width - length name - length stid) ' '
            val = pad ++ ": " ++ stid ++ ": " ++ st
        pure (name, val)
    width = 24

dumper :: ([String] -> IO ()) -> IO ()
dumper putLines = forever $ do
    putLines =<< (dumpThreads <&> (++ ["----------------------------------------"]))
    threadDelay interval
  where
    interval = 3 * 1000 * 1000

---

async :: String -> IO a -> IO (Async a)
async name io = do
    a <- Async.async io
    labelThread (asyncThreadId a) name
    pure a

withAsync :: String -> IO a -> (Async a -> IO b) -> IO b
withAsync name io h0 =
    Async.withAsync io h
  where
    h a = do
        labelThread (asyncThreadId a) name
        h0 a

withAsyncs ::  [(String, IO a)] -> ([Async a] -> IO b) -> IO b
withAsyncs ps h = foldr op (\f -> h (f [])) ps id
  where
    op (n, io) action = \s -> withAsync n io $ \a -> action (s . (a:))

{- FOURMOLU_DISABLE -}
concurrently :: String -> IO a -> String -> IO b -> IO (a, b)
concurrently nleft left nright right =
    withAsync nleft  left $ \a ->
    withAsync nright right $ \b ->
    Async.waitBoth a b
{- FOURMOLU_ENABLE -}

concurrently_ :: String -> IO a -> String -> IO b -> IO ()
concurrently_ nleft left nright right = void $ concurrently nleft left nright right

{- FOURMOLU_DISABLE -}
race :: String -> IO a -> String -> IO b -> IO (Either a b)
race nleft left nright right =
    withAsync nleft  left $ \a ->
    withAsync nright right $ \b ->
    Async.waitEither a b
{- FOURMOLU_ENABLE -}

race_ :: String -> IO a -> String -> IO b -> IO ()
race_ nleft left nright right = void $ race nleft left nright right

-- |
-- >>> concurrentlyList $ zip [[c] | c <- ['a'..]] [pure x | x <- [1::Int .. 5]]
-- [1,2,3,4,5]
concurrentlyList :: [(String, IO a)] -> IO [a]
concurrentlyList ps = withAsyncs ps $ mapM Async.wait

concurrentlyList_ :: [(String, IO a)] -> IO ()
concurrentlyList_ = void . concurrentlyList

raceList :: [(String, IO a)] -> IO (Async a, a)
raceList ps = withAsyncs ps $ Async.waitAny

raceList_ :: [(String, IO a)] -> IO ()
raceList_ = void . raceList
