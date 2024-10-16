{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Iterative.Server.NonBlocking (
    -- * Non-blocking RecvN
    NBRecv,
    NBRecvN,
    NBRecvR (..),
    makeNBRecvVC,

    -- * for testing
    makeNBRecvN,
)
where

import qualified Control.Exception as E
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef

import DNS.Do53.Internal
import DNS.Types

data NBRecvR = EOF ByteString | NotEnough | NBytes ByteString
    deriving (Eq, Show)

type NBRecv = IO NBRecvR
type NBRecvN = Int -> IO NBRecvR

type Buffer = [ByteString] -> [ByteString]

makeNBRecvVC :: VCLimit -> Recv -> IO NBRecv
makeNBRecvVC lim rcv = do
    ref <- newIORef LNone
    nbrecvN <- makeNBRecvN "" rcv
    return $ nbRecvVC lim ref nbrecvN

makeNBRecvN :: ByteString -> Recv -> IO NBRecvN
makeNBRecvN "" rcv = nbRecvN rcv <$> newIORef (0, id)
makeNBRecvN bs0 rcv = nbRecvN rcv <$> newIORef (len, (bs0 :))
  where
    len = BS.length bs0

data FillLen = LNone | LHigh | LFilled Int

nbRecvVC :: VCLimit -> IORef FillLen -> NBRecvN -> NBRecv
nbRecvVC lim ref nbrecvN = do
    mi <- readIORef ref
    case mi of
        LNone -> getLen >>= caseFillLen
        LHigh -> getLen >>= caseFillLen
        LFilled len -> nbrecvN len
  where
    getLen = nbrecvN 2
    caseFillLen x = case x of
        NBytes bs -> nbytes bs
        NotEnough -> do
            writeIORef ref LHigh
            return NotEnough
        e@(EOF _bs) -> return e {- got EOF when getting length -}
    nbytes bs = do
        let len = decodeVCLength bs
        when (fromIntegral len > lim) $
            E.throwIO $
                DecodeError $
                    "length is over the limit: should be len <= lim, but (len: "
                        ++ show len
                        ++ ") > (lim: "
                        ++ show lim
                        ++ ") "
        writeIORef ref $ LFilled len
        return NotEnough

nbRecvN
    :: Recv
    -> IORef (Int, Buffer)
    -> NBRecvN
nbRecvN rcv ref n = do
    (len0, build0) <- readIORef ref
    if
        | len0 == n -> do
            writeIORef ref (0, id)
            return $ NBytes $ BS.concat $ build0 []
        | len0 > n -> do
            let bs = BS.concat $ build0 []
                (ret, left) = BS.splitAt n bs
            writeIORef ref (BS.length left, (left :))
            return $ NBytes ret
        | otherwise -> do
            bs1 <- rcv
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
                            let (bs3, left) = BS.splitAt (n - len0) bs1
                            writeIORef ref (BS.length left, (left :))
                            return $ NBytes $ BS.concat $ build0 [bs3]
                        | otherwise -> do
                            writeIORef ref (len2, build0 . (bs1 :))
                            return NotEnough
