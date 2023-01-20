module DNS.Do53.Id (
    singleGenId
  , newConcurrentGenId
  ) where

import Data.Array
import Control.Concurrent
import Control.Monad
import DNS.Types
import System.Random.Stateful (globalStdGen, uniformWord16, newAtomicGenM, initStdGen)

singleGenId :: IO Identifier
singleGenId = uniformWord16 globalStdGen

newConcurrentGenId :: IO (IO Identifier)
newConcurrentGenId = do
    n <- getNumCapabilities
    gs <- replicateM n (initStdGen >>= newAtomicGenM)
    let arr = listArray (0, n - 1) gs
    return $ do
        (i, _) <- myThreadId >>= threadCapability
        uniformWord16 (arr ! i)
