module DNS.Do53.Memo (
    Cache
  , Key
  , Entry
  , newCache
  , insertCache
  , lookupCache
  ) where

import qualified Control.Reaper as R
import DNS.Types
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ

import DNS.Do53.Imports

type Key = Question
type Prio = EpochTime

type Entry = Either DNSError [RData]

type DB = OrdPSQ Key Prio Entry

-- | Cache for resource records.
newtype Cache = Cache (R.Reaper DB (Key,Prio,Entry))

newCache :: Int -> IO Cache
newCache delay = Cache <$> R.mkReaper R.defaultReaperSettings {
    R.reaperEmpty    = PSQ.empty
  , R.reaperCons     = \(k, tim, v) psq -> PSQ.insert k tim v psq
  , R.reaperAction   = mkPrune
  , R.reaperDelay    = delay * 1000000
  , R.reaperNull     = PSQ.null
  , R.reaperMergable = False
  }

lookupCache :: Key -> Cache -> IO (Maybe (Prio, Entry))
lookupCache key (Cache reaper) = PSQ.lookup key <$> R.reaperRead reaper

insertCache :: Key -> Prio -> Entry -> Cache -> IO ()
insertCache key tim ent (Cache reaper) = R.reaperAdd reaper (key,tim,ent)

mkPrune :: DB -> IO (DB -> DB)
mkPrune _db = do
    tim <- getEpochTime
    let prune = snd . PSQ.atMostView tim
    return prune
