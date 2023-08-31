{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNSTAP (
    DnstapQ,
    writeDnstapQ,
    composeMessage,
    newDnstapWriter,
) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified DNS.TAP.FastStream as FSTRM
import DNS.TAP.Schema
import DNS.Types
import Data.ByteString (ByteString)
import Network.Socket
import qualified UnliftIO.Exception as E

import Config

newtype DnstapQ = DnstapQ (TQueue Message)

newDnstapQ :: IO DnstapQ
newDnstapQ = DnstapQ <$> newTQueueIO

composeMessage :: ByteString -> Message
composeMessage bs =
    defaultMessage
        { messageResponseMessage = Just $ Left (UnknownDNSError, bs) -- fixme: dummy
        }

writeDnstapQ :: DnstapQ -> Message -> IO ()
writeDnstapQ (DnstapQ q) msg = atomically $ writeTQueue q msg

readDnsTapQ :: DnstapQ -> IO Message
readDnsTapQ (DnstapQ q) = atomically $ readTQueue q

newDnstapWriter :: Config -> IO (IO (), Message -> IO ())
newDnstapWriter conf = do
    q <- newDnstapQ
    return (control (exec conf q), writeDnstapQ q)

exec :: Config -> DnstapQ -> IO ()
exec Config{..} q = E.bracket setup close $ \sock -> do
    let fconf = FSTRM.Config True False
    FSTRM.writer sock fconf $ do
        msg <- readDnsTapQ q
        let d = defaultDNSTAP{dnstapMessage = Just msg}
        return $ encodeDnstap d
  where
    setup = E.bracketOnError open close conn
      where
        open = socket AF_UNIX Stream defaultProtocol
        conn sock = do
            connect sock $ SockAddrUnix cnf_dnstap_socket_path
            return sock

control :: IO () -> IO ()
control body = do
    ex <- E.try body
    case ex of
        Right () -> return ()
        Left (E.SomeException _e) -> do
            threadDelay 60000000 -- fixme
            control body
