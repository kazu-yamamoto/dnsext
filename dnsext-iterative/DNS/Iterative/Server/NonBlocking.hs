{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Iterative.Server.NonBlocking (
    -- * Non-blocking size specified recv
    NBRecvR (..),
    makeNBRecvVC,

    -- * for testing
    makeNBRecvN,

    -- * to fix
    makeNBRecvVCNoSize,
)
where

import qualified Control.Exception as E
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef

import DNS.Do53.Internal (VCLimit, decodeVCLength)
import DNS.Types

data NBRecvR = EOF ByteString | NotEnough | NBytes ByteString
    deriving (Eq, Show)

type BS = ByteString
type Buffer = [ByteString] -> [ByteString]

{-# WARNING makeNBRecvVCNoSize "should not recv data not received by app for right socket readable state" #-}
makeNBRecvVCNoSize :: VCLimit -> IO BS -> IO (IO NBRecvR)
makeNBRecvVCNoSize lim rcv = makeNBRecvVC lim $ \_ -> rcv

makeNBRecvVC :: VCLimit -> (Int -> IO BS) -> IO (IO NBRecvR)
makeNBRecvVC lim rcv = do
    ref <- newIORef Nothing
    nbrecvN <- makeNBRecvN "" rcv
    return $ nbRecvVC lim ref nbrecvN

makeNBRecvN :: ByteString -> (Int -> IO BS) -> IO (Int -> IO NBRecvR)
makeNBRecvN "" rcv = nbRecvN rcv <$> newIORef (0, id)
makeNBRecvN bs0 rcv = nbRecvN rcv <$> newIORef (len, (bs0 :))
  where
    len = BS.length bs0

nbRecvVC :: VCLimit -> IORef (Maybe Int) -> (Int -> IO NBRecvR) -> IO NBRecvR
nbRecvVC lim ref nbrecvN = do
    mi <- readIORef ref
    case mi of
        Nothing -> do
            x <- nbrecvN 2
            case x of
                NBytes bs -> do
                    let len = decodeVCLength bs
                    when (fromIntegral len > lim) $
                        E.throwIO $
                            DecodeError $
                                "length is over the limit: should be len <= lim, but (len: "
                                    ++ show len
                                    ++ ") > (lim: "
                                    ++ show lim
                                    ++ ") "
                    writeIORef ref $ Just len
                    return NotEnough
                _ -> return x
        Just len -> nbrecvN len

nbRecvN
    :: (Int -> IO BS)
    -> IORef (Int, Buffer)
    -> (Int -> IO NBRecvR)
nbRecvN rcv ref n = do
    (len0, build0) <- readIORef ref
    if
        | len0 == n -> do
            writeIORef ref (0, id)
            return $ NBytes $ BS.concat $ build0 []
        | len0 > n -> do
            {- only wrong, over-sized case -}
            let bs = BS.concat $ build0 []
                (ret, left) = BS.splitAt n bs
            writeIORef ref (BS.length left, (left :))
            return $ NBytes ret
        | otherwise -> do
            bs1 <- rcv (n - len0)
            if BS.null bs1
                then do
                    writeIORef ref (0, id)
                    return $ EOF $ BS.concat $ build0 []
                else do
                    let len1 = BS.length bs1
                        len2 = len0 + len1
                    if
                        | len2 == n -> do
                            writeIORef ref (0, id)
                            return $ NBytes $ BS.concat $ build0 [bs1]
                        | len2 > n -> do
                            {- only wrong, over-sized case -}
                            let (bs3, left) = BS.splitAt (n - len0) bs1
                            writeIORef ref (BS.length left, (left :))
                            return $ NBytes $ BS.concat $ build0 [bs3]
                        | otherwise -> do
                            writeIORef ref (len2, build0 . (bs1 :))
                            return NotEnough
