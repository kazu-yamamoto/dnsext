{-# LANGUAGE OverloadedStrings #-}

module NonBlockingSpec where

import Data.ByteString (ByteString)
import Data.IORef
import Test.Hspec (Spec, describe, hspec, it, shouldReturn)

import DNS.Iterative.Server

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
    describe "NBRecvN" $ do
        it "should work well" $ do
            testNBRecvN "" [] 5 [EOF "", EOF "", EOF ""]
            testNBRecvN "" ["abcde"] 5 [NBytes "abcde", EOF ""]
            testNBRecvN
                ""
                ["abcdefgh"]
                5
                [NBytes "abcde", EOF "fgh", EOF ""]

            testNBRecvN
                ""
                ["ab", "cdefgh"]
                5
                [NotEnough, NBytes "abcde", EOF "fgh", EOF ""]
            testNBRecvN
                ""
                ["a", "b", "c", "d", "e", "f", "g", "h"]
                5
                [ NotEnough
                , NotEnough
                , NotEnough
                , NotEnough
                , NBytes "abcde"
                , NotEnough
                , NotEnough
                , NotEnough
                , EOF "fgh"
                , EOF ""
                ]

            testNBRecvN "xyz" [] 2 [NBytes "xy", EOF "z", EOF "", EOF ""]
            testNBRecvN "xyz" [] 5 [EOF "xyz", EOF "", EOF ""]
            testNBRecvN "xyz" ["ab"] 5 [NBytes "xyzab", EOF "", EOF ""]
            testNBRecvN
                "xyz"
                ["abcdefgh"]
                5
                [NBytes "xyzab", NBytes "cdefg", EOF "h", EOF ""]

            testNBRecvN
                "xyz"
                ["ab", "cdefgh"]
                5
                [NBytes "xyzab", NBytes "cdefg", EOF "h", EOF ""]
            testNBRecvN
                "xyz"
                ["a", "b", "c", "d", "e", "f", "g", "h"]
                5
                [ NotEnough
                , NBytes "xyzab"
                , NotEnough
                , NotEnough
                , NotEnough
                , NotEnough
                , NBytes "cdefg"
                , NotEnough
                , EOF "h"
                , EOF ""
                ]

testNBRecvN
    :: ByteString -> [ByteString] -> Int -> [NBRecvR] -> IO ()
testNBRecvN ini xs n ress = do
    rcv <- makeRecv xs
    nbRecvN <- makeNBRecvN ini rcv
    mapM_ (nbRecvN n `shouldReturn`) ress

makeRecv :: [ByteString] -> IO (IO ByteString)
makeRecv xs0 = do
    ref <- newIORef xs0
    return $ rcv ref
  where
    rcv ref = do
        xss <- readIORef ref
        case xss of
            [] -> return ""
            x : xs -> do
                writeIORef ref xs
                return x
