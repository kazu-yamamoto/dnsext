{-# LANGUAGE RecordWildCards #-}

module DNSTAP (
    DnstapQ,
    writeDnstapQ,
    newDnstapWriter,
    Message,
) where

import Control.Concurrent
import Control.Concurrent.STM
import qualified DNS.TAP.FastStream as FSTRM
import DNS.TAP.Schema
import Network.Socket
import qualified UnliftIO.Exception as E

import Config

newtype DnstapQ = DnstapQ (TQueue Message)

newDnstapQ :: IO DnstapQ
newDnstapQ = DnstapQ <$> newTQueueIO

writeDnstapQ :: DnstapQ -> Message -> IO ()
writeDnstapQ (DnstapQ q) ~msg = atomically $ writeTQueue q msg

readDnsTapQ :: DnstapQ -> IO Message
readDnsTapQ (DnstapQ q) = atomically $ readTQueue q

newDnstapWriter :: Config -> IO (IO (), Message -> IO ())
newDnstapWriter conf = do
    q <- newDnstapQ
    let logger = control conf $ exec conf q
        put = writeDnstapQ q
    return (logger, put)

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

control :: Config -> IO () -> IO ()
control Config{..} body = loop
  where
    loop = do
        ex <- E.try body
        case ex of
            Right () -> return ()
            Left (E.SomeException _e) -> do
                threadDelay (cnf_dnstap_reconnect_interval * 1000000)
                loop
