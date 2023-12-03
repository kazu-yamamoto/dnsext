module DNS.Iterative.Server.WorkerStats where

-- GHC packages
import Data.Int (Int64)
import Data.IORef
import Data.List (sortBy, intercalate)
import Data.Ord (comparing)

-- dnsext-* packages
import qualified DNS.Types as DNS
import DNS.Types.Time (EpochTime, getCurrentTimeNsec)

pprWorkerStats :: Int -> [WorkerStatOP] -> IO [String]
pprWorkerStats pn ops = do
    stats <- zip [1 :: Int ..] <$> mapM getWorkerStat ops
    let isStat p = p . fst . snd
        qs = filter (isStat ((&&) <$> (/= WWaitDequeue) <*> (/= WWaitEnqueue))) stats
        {- sorted by query span -}
        sorted = sortBy (comparing $ (\(DiffT int) -> int) . snd . snd) qs
        deqs = filter (isStat (== WWaitDequeue)) stats
        enqs = filter (isStat (== WWaitEnqueue)) stats

        pprq (wn, st) = showDec3 wn ++ ": " ++ pprWorkerStat st
        workers []      = "no workers"
        workers triples = intercalate " " (map (\(wn, (_st, ds)) -> show wn ++ ":" ++ showDiffSec1 ds) triples)
        pprdeq = " waiting dequeues: " ++ show (length deqs) ++ " workers"
        pprenq = " waiting enqueues: " ++ workers enqs

    return $ map (("  " ++ show pn ++ ":") ++) $ map pprq sorted ++ [pprdeq, pprenq]
  where
    showDec3 n
        | 100 <= n    =  show n
        | 10  <= n    =  ' ' : show n
        | otherwise   =  "  " ++ show n

pprWorkerStat :: (WorkerStat, DiffTime) -> String
pprWorkerStat (stat, diff) = pad ++ diffStr ++ ": " ++ show stat
  where
    diffStr = showDiffSec1 diff
    pad = replicate (width - length diffStr) ' '
    width = 7

------------------------------------------------------------

{- FOURMOLU_DISABLE -}
data WorkerStat
    = WWaitDequeue
    | WRun DNS.Question
    | WWaitEnqueue
    deriving Eq

instance Show WorkerStat where
    show  WWaitDequeue                = "waiting Dequeue"
    show (WRun (DNS.Question n t _))  = "quering " ++ show n ++ " " ++ show t
    show  WWaitEnqueue                = "waiting Enqueue"
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
data WorkerStatOP =
    WorkerStatOP
    { setWorkerStat :: WorkerStat -> IO ()
    , getWorkerStat :: IO (WorkerStat, DiffTime)
    }
{- FOURMOLU_ENABLE -}

data WStatStore = WSStore WorkerStat TimeStamp

getWorkerStatOP :: IO WorkerStatOP
getWorkerStatOP = do
    ref <- newIORef =<< getStore WWaitDequeue
    pure $ WorkerStatOP (setStat ref) (getStat ref)
  where
    getStore stat = WSStore stat <$> getTimeStamp
    setStat ref stat = writeIORef ref =<< getStore stat
    getStat ref = do
        WSStore s ts0 <- readIORef ref
        now <- getTimeStamp
        return (s, now `diffTimeStamp` ts0)

------------------------------------------------------------

data TimeStamp = TS EpochTime Int64
newtype DiffTime = DiffT Integer

getTimeStamp :: IO TimeStamp
getTimeStamp = uncurry TS <$> getCurrentTimeNsec

toNanosec :: TimeStamp -> Integer
toNanosec (TS e n) = fromIntegral e * nanof + fromIntegral n
  where
    nanof = 1000 * 1000 * 1000

diffTimeStamp :: TimeStamp -> TimeStamp -> DiffTime
diffTimeStamp t1 t2 = DiffT $ toNanosec t1 - toNanosec t2

showDiffSec1 :: DiffTime -> String
showDiffSec1 (DiffT snsec)
    | snsec < 0  = '-' : str ++ "s"
    | otherwise  = str ++ "s"
  where
    nsec = abs snsec
    df = 100 * 1000 * 1000
    dsec = nsec `quot` df
    (sec, d) = dsec `quotRem` 10
    str = show sec ++ "." ++ show d
