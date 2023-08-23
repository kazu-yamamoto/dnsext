{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

-- Fast stream:
-- https://github.com/farsightsec/fstrm/blob/master/fstrm/control.h

module DNS.TAP.FastStream where

import Control.Exception as E
import Control.Monad
import qualified Data.ByteString.Char8 as C8
import Data.Typeable
import Data.Word
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.BufferPool as P
import qualified Network.Socket.ByteString as NSB

data Control = Control { fromControl :: Word32 } deriving (Eq, Show)

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
{- FOURMOLU_ENABLE -}

data FSException = FSException String deriving (Show, Typeable)

instance Exception FSException

data Config = Config
    { bidirectional :: Bool
    , isServer :: Bool
    , debug :: Bool
    }

data Context = Context
    { ctxRecv   :: Int -> IO ByteString
    , ctxSend   :: ByteString -> IO ()
    , ctxBidi   :: Bool
    , ctxServer :: Bool
    , ctxDebug  :: Bool
    }

newContext :: Socket -> Config -> IO Context
newContext s conf = do
    pool <- P.newBufferPool 512 16384
    recvN <- P.makeRecvN "" $ P.receive s pool
    return Context {
        ctxRecv = recvN
      , ctxSend = NSB.sendAll s
      , ctxBidi = bidirectional conf
      , ctxServer = isServer conf
      , ctxDebug = debug conf
      }

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

readLength :: Readable a => a -> IO Word32
readLength = read32

readControl :: Readable a => a -> IO Control
readControl rbuf = Control <$> read32 rbuf

readContent :: Readable a => a -> Word32 -> IO ByteString
readContent rbuf l = extractByteString rbuf $ fromIntegral l

check :: Control -> Control -> IO ()
check c ctrl = when (c /= ctrl) $ throwIO $ FSException ("no " ++ show ctrl)

handshake :: Context -> IO ()
handshake ctx@Context{..}
  | ctxServer = do
        c <- recvControl ctx
        check c ESCAPE
        bsx <- recvLength ctx >>= recvContent ctx
        withReadBuffer bsx $ \rbuf -> do
            s <- readControl rbuf
            check s START
            when ctxDebug $ putStrLn "START"
            a <- readControl rbuf
            check a ACCEPT
            when ctxDebug $ putStr "ACCEPT "
            bs <- readLength rbuf >>= readContent rbuf
            when ctxDebug $ C8.putStrLn bs
  | otherwise = do
        let len = undefined
        ctxSend $ bytestring32 $ fromControl ESCAPE
        ctxSend $ bytestring32 len
        ctxSend $ bytestring32 $ fromControl START

-- | "" returns on EOF
recvData :: Context -> IO ByteString
recvData ctx@Context{..}
  | ctxServer = do
        when ctxDebug $ putStrLn "--------------------------------"
        l <- recvLength ctx
        if l == 0 then do
            when ctxDebug $ putStrLn "STOP"
            return ""
          else do
            when ctxDebug $ putStrLn $ "fstrm data length: " ++ show l
            recvContent ctx l
  | otherwise = throwIO $ FSException "client cannot use recvData"

sendData :: Context -> ByteString -> IO ()
sendData Context{..} _bs
  | ctxServer = throwIO $ FSException "server cannot use sendData"
  | otherwise = undefined

bye :: Context -> IO ()
bye Context{..}
  | ctxServer = throwIO $ FSException "server cannot use bye"
  | otherwise = undefined
