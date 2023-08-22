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

handshake :: Context -> IO ()
handshake Context{..}
  | ctxServer = do
        bsc <- ctxRecv 4
        c <- withReadBuffer bsc $ \rbuf -> Control <$> read32 rbuf
        when (c /= ESCAPE) $ throwIO $ FSException "no ESCAPE"
        bsl <- ctxRecv 4
        l <- withReadBuffer bsl $ \rbuf -> fromIntegral <$> read32 rbuf
        bsx <- ctxRecv l
        withReadBuffer bsx $ \rbuf -> do
            s <- Control <$> read32 rbuf
            when (s /= START) $ throwIO $ FSException "no START"
            when ctxDebug $ putStrLn "START"
            a <- Control <$> read32 rbuf
            when (a /= ACCEPT) $ throwIO $ FSException "no ACCEPT"
            when ctxDebug $ putStr "ACCEPT "
            l1 <- read32 rbuf
            bs <- extractByteString rbuf $ fromIntegral l1
            when ctxDebug $ C8.putStrLn bs
  | otherwise = do
        let len = undefined
        ctxSend $ bytestring32 $ fromControl ESCAPE
        ctxSend $ bytestring32 len
        ctxSend $ bytestring32 $ fromControl START

-- | "" returns on EOF
recvData :: Context -> IO ByteString
recvData Context{..}
  | ctxServer = do
        bsl <- ctxRecv 4
        l <- withReadBuffer bsl $ \rbuf -> fromIntegral <$> read32 rbuf
        when ctxDebug $ putStrLn "--------------------------------"
        when ctxDebug $ putStrLn $ "fstrm data length: " ++ show l
        bsx <- ctxRecv l
        when ctxDebug $ do
            when (C8.length bsx == 0) $ putStrLn "STOP"
        return bsx
  | otherwise = throwIO $ FSException "client cannot use recvData"

sendData :: Context -> ByteString -> IO ()
sendData Context{..} _bs
  | ctxServer = throwIO $ FSException "server cannot use sendData"
  | otherwise = undefined

bye :: Context -> IO ()
bye Context{..}
  | ctxServer = throwIO $ FSException "server cannot use bye"
  | otherwise = undefined
