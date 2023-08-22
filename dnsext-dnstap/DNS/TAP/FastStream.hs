{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

-- Fast stream:
-- https://github.com/farsightsec/fstrm/blob/master/fstrm/control.h

module DNS.TAP.FastStream where

import Control.Exception as E
import Control.Monad
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as C8
import Data.Typeable
import Data.Word
import Network.ByteOrder
import Network.Socket
import qualified Network.Socket.BufferPool as P
import qualified Network.Socket.ByteString as NSB

data Control
    = ESCAPE
    | ACCEPT
    | START
    | STOP
    | READY
    | FINISH
    deriving (Eq, Show)

{- FOURMOLU_DISABLE -}
fromControl :: Control -> Word32
fromControl ESCAPE = 0x00
fromControl ACCEPT = 0x01
fromControl START  = 0x02
fromControl STOP   = 0x03
fromControl READY  = 0x04
fromControl FINISH = 0x05
{- FOURMOLU_ENABLE -}

toControl :: Word32 -> Maybe Control
toControl 0x00 = Just ESCAPE
toControl 0x01 = Just ACCEPT
toControl 0x02 = Just START
toControl 0x03 = Just STOP
toControl 0x04 = Just READY
toControl 0x05 = Just FINISH
toControl _ = Nothing

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
        c <- withReadBuffer bsc $ \rbuf -> toControl <$> read32 rbuf
        when (c /= Just ESCAPE) $ throwIO $ FSException "no ESCAPE"
        bsl <- ctxRecv 4
        l <- withReadBuffer bsl $ \rbuf -> fromIntegral <$> read32 rbuf
        bsx <- ctxRecv l
        withReadBuffer bsx $ \rbuf -> do
            s <- toControl <$> read32 rbuf
            when (s /= Just START) $ throwIO $ FSException "no START"
            when ctxDebug $ putStrLn "START"
            a <- toControl <$> read32 rbuf
            when (a /= Just ACCEPT) $ throwIO $ FSException "no ACCEPT"
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
        ctxRecv l
  | otherwise = throwIO $ FSException "client cannot use recvData"

sendData :: Context -> ByteString -> IO ()
sendData = undefined

bye :: Context -> IO ()
bye = undefined
