module DNS.Do53.Memo (
    Cache
  , Key
  , Entry
  , newCache
  , insertCache
  , lookupCache
  ) where

import Data.IORef (IORef, newIORef, readIORef, atomicModifyIORef')
import qualified DNS.Do53.OneShot as O
import DNS.Types
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ

import DNS.Do53.Imports

type Key = Question
type Prio = EpochTime

type Entry = Either DNSError [RData]

type DB = OrdPSQ Key Prio Entry

-- | Cache for resource records.
data Cache = Cache (IORef DB) O.OneShot

newCache :: Int -> IO Cache
newCache delay = do
  dbRef <- newIORef PSQ.empty
  Cache dbRef <$> O.mkOneShot O.defaultOneShotSettings {
    O.oneShotAction = \registerAgain -> prune dbRef *> onNotNull dbRef registerAgain
  , O.oneShotDelay = delay * 1000000
  }

lookupCache :: Key -> Cache -> IO (Maybe (Prio, Entry))
lookupCache key (Cache dbRef _) = PSQ.lookup key <$> readIORef dbRef

insertCache :: Key -> Prio -> Entry -> Cache -> IO ()
insertCache key tim ent (Cache dbRef oneShot) = do
  let ins db = (PSQ.insert key tim ent db, ())
  atomicModifyIORef' dbRef ins
  onNotNull dbRef (O.oneShotRegister oneShot)

onNotNull :: IORef DB -> IO () -> IO ()
onNotNull dbRef action = do
  nullP <- PSQ.null <$> readIORef dbRef
  unless nullP action

-- Theoretically speaking, atMostView itself is good enough for pruning.
-- But auto-update assumes a list based db which does not provide atMost
-- functions. So, we need to do this redundant way.
prune :: IORef DB -> IO ()
prune dbRef = do
  tim <- getEpochTime
  let modify oldpsq = (snd $ PSQ.atMostView tim oldpsq, ())
  atomicModifyIORef' dbRef modify
