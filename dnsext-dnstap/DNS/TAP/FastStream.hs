{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

-- Fast stream:
-- https://github.com/farsightsec/fstrm/blob/master/fstrm/control.h

module DNS.TAP.FastStream (
    Config (..),
    newContext,
    reader,
    handshake,
    recvData,
    sendData,
    bye,
) where

import UnliftIO.Exception as E
import Control.Monad
import qualified Data.ByteString.Char8 as C8
import Data.Word
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.BufferPool as P
import qualified Network.Socket.ByteString as NSB

data Control = Control {fromControl :: Word32} deriving (Eq)

{- FOURMOLU_DISABLE -}
pattern ESCAPE :: Control
pattern ESCAPE  = Control 0x00
pattern ACCEPT :: Control
pattern ACCEPT  = Control 0x01
pattern START  :: Control
pattern START   = Control 0x02
pattern STOP   :: Control
pattern STOP    = Control 0x03
pattern READY  :: Control
pattern READY   = Control 0x04
pattern FINISH :: Control
pattern FINISH  = Control 0x05

instance Show Control where
    show ESCAPE = "ESCAPE"
    show ACCEPT = "ACCEPT"
    show START  = "START"
    show STOP   = "STOP"
    show READY  = "READY"
    show FINISH = "FINISH"
    show (Control n) = "Control " ++ show n
{- FOURMOLU_ENABLE -}

data FieldType = FieldType {fromFieldType :: Word32} deriving (Eq, Show)

pattern ContentType :: FieldType
pattern ContentType = FieldType 0x01

data FSException = FSException String deriving (Show, Typeable)

instance Exception FSException

data Config = Config
    { bidirectional :: Bool
    , isServer :: Bool
    , debug :: Bool
    }

----------------------------------------------------------------

data Context = Context
    { ctxRecv :: Int -> IO ByteString
    , ctxSend :: [ByteString] -> IO ()
    , ctxBidi :: Bool
    , ctxServer :: Bool
    , ctxDebug :: Bool
    }

newContext :: Socket -> Config -> IO Context
newContext s conf = do
    pool <- P.newBufferPool 512 16384
    recvN <- P.makeRecvN "" $ P.receive s pool
    return
        Context
            { ctxRecv = recvN
            , ctxSend = NSB.sendMany s
            , ctxBidi = bidirectional conf
            , ctxServer = isServer conf
            , ctxDebug = debug conf
            }

----------------------------------------------------------------

recvLength :: Context -> IO Word32
recvLength Context{..} = do
    bsc <- ctxRecv 4
    unsafeWithByteString bsc peek32

recvControl :: Context -> IO Control
recvControl Context{..} = do
    bsc <- ctxRecv 4
    Control <$> unsafeWithByteString bsc peek32

recvContent :: Context -> Word32 -> IO ByteString
recvContent Context{..} l = ctxRecv $ fromIntegral l

----------------------------------------------------------------

-- ESCAPE is already received.
recvControlFrame :: Context -> Control -> IO ()
recvControlFrame ctx@Context{..} ctrl = do
    l0 <- recvLength ctx
    when (l0 < 4) $ throwIO $ FSException "illegal control length"
    c <- recvControl ctx
    check c ctrl
    when ctxDebug $ print ctrl
    let l1 = l0 - 4
    loop l1
  where
    loop 0 = return ()
    loop l = do
        when (l < 8) $ throwIO $ FSException "illegal field length"
        ft <- FieldType <$> recvLength ctx
        l0 <- recvLength ctx
        ct <- recvContent ctx l0
        if ft == ContentType
            then do
                when ctxDebug $ do
                    putStr "Content-Type: "
                    C8.putStrLn ct
            else when ctxDebug $ putStrLn "unknown field"
        loop (l - 8 - l0)

check :: Control -> Control -> IO ()
check c ctrl = when (c /= ctrl) $ throwIO $ FSException ("no " ++ show ctrl)

sendControlFrame :: Context -> Control -> IO ()
sendControlFrame Context{..} ctrl = do
    let esc = bytestring32 $ fromControl ESCAPE
        len = bytestring32 4
        ctr = bytestring32 $ fromControl ctrl
    ctxSend [esc, len, ctr]

----------------------------------------------------------------
-- API

handshake :: Context -> IO ()
handshake ctx@Context{..}
    | ctxServer = do
        c <- recvControl ctx
        check c ESCAPE
        recvControlFrame ctx START
        when ctxBidi $ sendControlFrame ctx ACCEPT
    | otherwise = sendControlFrame ctx START

-- | "" returns on EOF
recvData :: Context -> IO ByteString
recvData ctx@Context{..}
    | ctxServer = do
        l <- recvLength ctx
        when ctxDebug $ putStrLn "--------------------------------"
        if l == 0
            then return ""
            else do
                when ctxDebug $ putStrLn $ "fstrm data length: " ++ show l
                bs <- recvContent ctx l
                when ctxBidi $ sendControlFrame ctx READY
                return bs
    | otherwise = throwIO $ FSException "client cannot use recvData"

sendData :: Context -> ByteString -> IO ()
sendData Context{..} _bs
    | ctxServer = throwIO $ FSException "server cannot use sendData"
    | otherwise = undefined

bye :: Context -> IO ()
bye ctx@Context{..}
    | ctxServer = do
        recvControlFrame ctx STOP
        sendControlFrame ctx FINISH `E.catch` \(E.SomeException _) -> return ()
    | otherwise = do
        sendControlFrame ctx STOP
        recvControlFrame ctx FINISH

----------------------------------------------------------------

reader :: Context -> (ByteString -> IO ()) -> IO ()
reader ctx body = do
    handshake ctx
    loop
    bye ctx
  where
    loop = do
        bs <- recvData ctx
        if C8.length bs == 0
            then return ()
            else do
                body bs
                loop
