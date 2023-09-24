
-- NSEC/NSEC3 Negative range cache
module DNS.RangeCache.Types (
    lookupCovered,

    -- * low-level interface
    lookupAlive,
)
where

-- GHC packages
import Control.Monad
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

-- others
import Data.OrdPSQ (OrdPSQ)
import qualified Data.OrdPSQ as PSQ

-- dnsext packages
import DNS.Types (Domain, TTL)
import DNS.Types.Decode (EpochTime)

---

type ZCache rk rrec = OrdPSQ rk EpochTime rrec
data RCache rk rrec = RCache (Map Domain (ZCache rk rrec)) Int {- max size -}

empty :: Int -> RCache rk rrec
empty = RCache Map.empty

null :: RCache rk rrec -> Bool
null (RCache m _) = Map.null m

{- FOURMOLU_DISABLE -}
lookupCovered
    :: Ord rk
    => (rrec -> rk)
    -> EpochTime -> Domain -> rk -> RCache rk rrec
    -> (TTL -> rk -> rrec -> Maybe a)
    -> Maybe a
lookupCovered getUpper now zone k cache mk =
    lookupAlive PSQ.lookupLT now zone k cache $
    \ttl kl recu -> do
        let ku = getUpper recu
            covered
                | kl < ku    = kl < k && k < ku
                | otherwise  = k < ku || kl < k  {- rotated range case -}
        guard covered
        mk ttl kl recu
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
lookupOverlap getUpper now zone qkl qrecu cache mk =
    lookupAlive PSQ.lookupLT now zone qku cache $
    \ttl kl recu -> do
        let ku = getUpper recu
            overlapped
                {- assumes `kl < qku` becase of `lookupLT` result -}
                {- {- covered query lower -}  kl  <= qkl && qkl <  ku  ||
                   {- covered query upper -}  kl  <  qku && qku <= ku  ||
                   {- covered query both  -}  kl  <= qkl && qku <= ku  ||
                   {- covered by query    -}  qkl <= kl  && ku  <= qku    -}
                | kl < ku    = qkl < ku  {- iff above 4 cases -}
                | otherwise  = undefined
        mk ttl kl recu
  where
    qku = getUpper qrecu
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
lookupAlive
    :: (rk -> ZCache rk rrec -> Maybe (rk, EpochTime, rrec))
    -> EpochTime -> Domain -> rk -> RCache rk rrec
    -> (TTL -> rk -> rrec -> Maybe a)
    -> Maybe a
lookupAlive lk now zone k (RCache c _) mk = do
    psq <- Map.lookup zone c
    (kl, eol, recu)  <- lk k psq
    ttl <- alive now eol
    mk ttl kl recu
{- FOURMOLU_ENABLE -}

alive :: EpochTime -> EpochTime -> Maybe TTL
alive now eol = do
    let ttl' = eol - now
        safeToTTL :: EpochTime -> Maybe TTL
        safeToTTL sec = do
            let y = fromIntegral sec
            guard $ toInteger y == toInteger sec
            return y
    guard $ ttl' >= 1
    safeToTTL ttl'
