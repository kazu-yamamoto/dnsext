module DNS.Do53.Id (
    singleGenId,
    newConcurrentGenId,
)
where

import Control.Concurrent
import Control.Monad
import DNS.Types
import Data.Array
import System.Random.Stateful (
    globalStdGen,
    initStdGen,
    newAtomicGenM,
    uniformWord16,
 )

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
