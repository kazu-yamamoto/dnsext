{-# LANGUAGE OverloadedStrings #-}

module NonBlockingSpec where

import Data.ByteString (ByteString)
import Data.Functor
import Data.IORef
import Data.String
import Test.Hspec (Spec, describe, hspec, it, shouldReturn)
import Test.Hspec.Expectations.Contrib (annotate)

import DNS.Iterative.Server

main :: IO ()
main = hspec spec

{- FOURMOLU_DISABLE -}
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
    specReadable

specReadable :: Spec
specReadable = do
    describe "NBRecvN readable" $ do
        it "eof" $ do
            testNBRecvNReadable
                [ (Close, True, [ (3, EOF "", False) ])
                ]
        it "not-enough" $ do
            testNBRecvNReadable
                [ (Bytes "abc", True, [ (5, NotEnough, False) ])
                , (Close      , True, [])
                ]
        it "n-bytes - just" $ do
            testNBRecvNReadable
                [ (Bytes "abc", True, [ (3, NBytes "abc", False) ])
                , (Close      , True, [ (3, EOF ""      , False) ])
                ]
        it "n-bytes - over" $ do
            testNBRecvNReadable
                [ (Bytes "abcdef", True, [ (3, NBytes "abc", True) ])
                , (Close         , True, [ (3, NBytes "def", True)
                                         , (3, EOF ""      , False) ])
                ]
        it "like VC dns message" $ do
            testNBRecvNReadable
                [ (Bytes ("\x00\x07" <> "abcdefg"), True, [ (2, NBytes "\x00\x07", True)
                                                          , (7, NBytes "abcdefg" , False)
                                                          ])
                , (Close                          , True, [ (2, EOF ""          , False) ])
                ]
{- FOURMOLU_ENABLE -}

testNBRecvN
    :: ByteString -> [ByteString] -> Int -> [NBRecvR] -> IO ()
testNBRecvN ini xs n ress = do
    rcv <- makeRecv xs
    nbRecvN <- makeNBRecvN ini (\_ -> rcv)
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

---

testNBRecvNReadable
    :: [(InEvent, Bool, [(Int, NBRecvR, Bool)])] -> IO ()
testNBRecvNReadable xs = do
    (readable, pushEv, rcv) <- makeSizedRecv
    nbrecvN <- makeNBRecvN "" rcv
    readable `shouldReturn` False
    let check i j (sz, exnbr, exrd) = do
            let ix = show i ++ ": " ++ show j ++ ": "
            annotate (ix ++ "nbrecv result") $ nbrecvN sz `shouldReturn` exnbr
            annotate (ix ++ "readable after recv") $ readable `shouldReturn` exrd
        action i (ev, exrd0, ys) = do
            pushEv ev
            annotate (show i ++ ": readable after event") $ readable `shouldReturn` exrd0
            sequence_ $ zipWith (check i) [(1 :: Int) ..] ys
    sequence_ $ zipWith action [(1 :: Int) ..] xs

data InEvent
    = Bytes String
    | Close
    deriving (Show)

data InState'
    = Arrived String
    | EndOfInput String
    | NoArrived
    deriving (Show)

type InState = IORef (Maybe InState')

{- FOURMOLU_DISABLE -}
readable' :: Maybe InState' -> Bool
readable' (Just (Arrived {}))     = True
readable' (Just  NoArrived)       = False
readable' (Just (EndOfInput {}))  = True
readable'  Nothing                = False

arrive :: IORef (Maybe InState') -> InEvent -> IO ()
arrive is e0 = do
    m <- readIORef is
    arrive' m e0
  where
    arrive' (Just (Arrived s0))     (Bytes s)   = writeIORef is $ Just $ Arrived (s0 ++ s)
    arrive' (Just (Arrived s0))      Close      = writeIORef is $ Just $ EndOfInput s0
    arrive' (Just  NoArrived)       (Bytes "")  = writeIORef is $ Just   NoArrived
    arrive' (Just  NoArrived)       (Bytes s)   = writeIORef is $ Just $ Arrived s
    arrive' (Just  NoArrived)        Close      = writeIORef is $ Just $ EndOfInput ""
    arrive' (Just (EndOfInput _))    e          = fail $ "wrong input state, input-event after eof: " ++ show e
    arrive'  Nothing                 e          = fail $ "wrong input state, input-event after closed: " ++ show e

consume :: IORef (Maybe InState') -> Int -> IO ByteString
consume is sz = do
    consume' =<< readIORef is
  where
    consume'  Nothing                = fail $ "cannot consume. after closed"
    consume' (Just NoArrived)        = fail $ "cannot consume. no-avail data, blocked"
    consume' (Just (EndOfInput ""))  = writeIORef is  Nothing $> ""
    consume' (Just (EndOfInput s0))  = writeIORef is (Just next) $> fromString hd
      where
        next
            | null tl    = EndOfInput ""
            | otherwise  = EndOfInput tl
        (hd, tl) = splitAt sz s0
    consume' (Just (Arrived s0))     = writeIORef is (Just next) $> fromString hd
      where
        next
            | null tl    = NoArrived
            | otherwise  = Arrived tl
        (hd, tl) = splitAt sz s0
{- FOURMOLU_ENABLE -}

makeSizedRecv :: IO (IO Bool, InEvent -> IO (), Int -> IO ByteString)
makeSizedRecv = do
    inSt <- newIORef $ Just NoArrived
    let readable = readable' <$> readIORef inSt
    return (readable, arrive inSt, consume inSt)
