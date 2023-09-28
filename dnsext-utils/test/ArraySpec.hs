module ArraySpec where

import Control.Concurrent.Async
import DNS.Array
import Data.Array.IO
import Test.Hspec

arraySize :: Int
arraySize = 10

threadNumber :: Int
threadNumber = 100

repeatNumber :: Int
repeatNumber = 10000

spec :: Spec
spec = do
    describe "atomicModifyArray" $ do
        it "can update atomically" $ do
            launch `shouldReturn` (threadNumber * repeatNumber)

launch :: IO Int
launch = do
    arr <- newArray (0, arraySize - 1) 0 :: IO (IOUArray Int Int)
    foldr concurrently_ (return ()) $ replicate threadNumber (update arr)
    sumIt 0 arr 0
  where
    sumIt ix arr acc
        | ix == arraySize = return acc
        | otherwise = do
            n <- readArray arr ix
            sumIt (ix + 1) arr (acc + n)

update :: IOUArray Int Int -> IO ()
update arr = loop 0
  where
    loop i
        | i == repeatNumber = return ()
        | otherwise = do
            let ix = i `mod` arraySize
            _ <- atomicModifyIntArray arr ix (+ 1)
            loop (i + 1)
