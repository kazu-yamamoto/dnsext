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

data State = E | S ByteString | M ([ByteString] -> [ByteString])

makeNBRecvVC :: VCLimit -> Recv -> IO NBRecv
makeNBRecvVC lim rcv = do
    ref <- newIORef Nothing
    nbrecvN <- makeNBRecvN rcv ""
    return $ nbRecvVC lim ref nbrecvN

makeNBRecvN :: Recv -> ByteString -> IO NBRecvN
makeNBRecvN rcv "" = nbRecvN rcv <$> newIORef (0, E)
makeNBRecvN rcv bs0 = nbRecvN rcv <$> newIORef (len, S bs0)
  where
    len = BS.length bs0

nbRecvVC :: VCLimit -> IORef (Maybe Int) -> NBRecvN -> NBRecv
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
    :: Recv
    -> IORef (Int, State)
    -> NBRecvN
nbRecvN rcv ref n = do
    (len0, st) <- readIORef ref
    if
        | len0 == n -> do
            writeIORef ref (0, E)
            case st of
                E -> return $ NBytes ""
                S bs0 -> return $ NBytes bs0
                M build0 -> return $ NBytes $ BS.concat $ build0 []
        | len0 > n -> do
            case st of
                E -> error "nbRecvN E"
                S bs0 -> do
                    let (ret, left) = BS.splitAt n bs0
                    writeIORef ref (BS.length left, S left)
                    return $ NBytes ret
                M build0 -> do
                    -- slow path
                    let bs = BS.concat $ build0 []
                        (ret, left) = BS.splitAt n bs
                    writeIORef ref (BS.length left, S left)
                    return $ NBytes ret
        | otherwise -> do
            bs1 <- rcv
            if BS.null bs1
                then do
                    writeIORef ref (0, E)
                    case st of
                        E -> return $ EOF ""
                        S bs -> return $ EOF bs
                        M build -> return $ EOF $ BS.concat $ build []
                else do
                    let len1 = BS.length bs1
                        len2 = len0 + len1
                    if
                        | len2 == n -> do
                            writeIORef ref (0, E)
                            case st of
                                E -> return $ NBytes bs1
                                S bs0 -> return $ NBytes (bs0 <> bs1)
                                M build0 -> return $ NBytes $ BS.concat $ build0 [bs1]
                        | len2 > n -> do
                            let (bs3, left) = BS.splitAt (n - len0) bs1
                            writeIORef ref (BS.length left, S left)
                            case st of
                                E -> return $ NBytes bs3
                                S bs0 -> return $ NBytes (bs0 <> bs3)
                                M build0 -> return $ NBytes $ BS.concat $ build0 [bs3]
                        | otherwise -> do
                            case st of
                                E -> writeIORef ref (len2, S bs1)
                                S bs0 -> writeIORef ref (len2, M ((bs0 :) . (bs1 :)))
                                M build0 -> writeIORef ref (len2, M (build0 . (bs1 :)))
                            return NotEnough
