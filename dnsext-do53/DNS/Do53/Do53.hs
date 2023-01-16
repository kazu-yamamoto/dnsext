{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Do53 (
    udpTcpSolver
  , udpSolver
  , tcpSolver
  , defaultResolvConf
  ) where

import Control.Exception as E
import DNS.Types
import DNS.Types.Decode
import Network.Socket (HostName, close)
import qualified Network.UDP as UDP
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Query
import DNS.Do53.Types

-- | Check response for a matching identifier and question.  If we ever do
-- pipelined TCP, we'll need to handle out of order responses.  See:
-- https://tools.ietf.org/html/rfc7766#section-7
--
checkResp :: Question -> Identifier -> DNSMessage -> Bool
checkResp q seqno = isNothing . checkRespM q seqno

-- When the response 'RCODE' is 'FormatErr', the server did not understand our
-- query packet, and so is not expected to return a matching question.
--
checkRespM :: Question -> Identifier -> DNSMessage -> Maybe DNSError
checkRespM q seqno resp
  | identifier (header resp) /= seqno = Just SequenceNumberMismatch
  | FormatErr <- rcode $ flags $ header resp
  , []        <- question resp        = Nothing
  | [q] /= question resp              = Just QuestionMismatch
  | otherwise                         = Nothing

----------------------------------------------------------------

data TCPFallback = TCPFallback deriving (Show, Typeable)
instance Exception TCPFallback

-- UDP attempts must use the same ID and accept delayed answers
-- but we use a fresh ID for each TCP lookup.
--
udpTcpSolver :: Solver
udpTcpSolver si = udpSolver si `E.catch` \TCPFallback -> tcpSolver si

----------------------------------------------------------------

ioErrorToDNSError :: HostName -> String -> IOError -> IO DNSMessage
ioErrorToDNSError h protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = protoName ++ "@" ++ h
    aioe = annotateIOError ioe loc Nothing Nothing

----------------------------------------------------------------

-- This throws DNSError or TCPFallback.
udpSolver :: Solver
udpSolver si@SolvInfo{..} =
    E.handle (ioErrorToDNSError solvHostName "udp") $
      bracket open UDP.close $ \sock -> do
        let send = UDP.send sock
            recv = UDP.recv sock
        res <- solve send recv si
        let fl = flags $ header res
            tc = trunCation fl
            rc = rcode fl
            eh = ednsHeader res
            qctl = ednsEnabled FlagClear <> solvQueryControls
        if tc then E.throwIO TCPFallback
        else if rc == FormatErr && eh == NoEDNS && qctl /= solvQueryControls
        then solve send recv si
        else return res

  where
    open = UDP.clientSocket solvHostName (show solvPortNumber) True -- connected

----------------------------------------------------------------

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.
-- This throws DNSError only.
tcpSolver :: Solver
tcpSolver si@SolvInfo{..} =
    E.handle (ioErrorToDNSError solvHostName "tcp") $ do
      bracket (openTCP solvHostName solvPortNumber) close $ \sock -> do
        let send = sendVC $ sendTCP sock
            recv = recvVC $ recvTCP sock
        res <- solve send recv si
        let fl = flags $ header res
            rc = rcode fl
            eh = ednsHeader res
            qctl = ednsEnabled FlagClear <> solvQueryControls
        -- If we first tried with EDNS, retry without on FormatErr.
        if rc == FormatErr && eh == NoEDNS && qctl /= solvQueryControls
        then solve send recv si
        else return res

----------------------------------------------------------------

solve :: (ByteString -> IO ())
      -> IO ByteString
      -> SolvInfo
      -> IO DNSMessage
solve send recv SolvInfo{..} = go solvRetry
  where
    go 0 = E.throwIO RetryLimitExceeded
    go cnt = do
        ident <- solvGenId
        let qry = encodeQuery ident solvQuestion solvQueryControls
        mres <- solvTimeout $ do
            send qry
            getAnswer solvQuestion ident recv solvGetTime
        case mres of
           Nothing  -> go (cnt - 1)
           Just res -> return res

getAnswer :: Question -> Identifier -> IO ByteString -> IO EpochTime -> IO DNSMessage
getAnswer q ident recv getTime = go
  where
    go = do
        now <- getTime
        bs <- recv `E.catch` \e -> E.throwIO $ NetworkFailure e
        case decodeAt now bs of
            Left  e   -> E.throwIO e
            Right msg
              | checkResp q ident msg -> return msg
              | otherwise             -> go

-- | Return a default 'ResolvConf':
--
-- * 'resolvInfo' is 'RCFilePath' \"\/etc\/resolv.conf\".
-- * 'resolvTimeout' is 3,000,000 micro seconds.
-- * 'resolvRetry' is 3.
-- * 'resolvConcurrent' is False.
-- * 'resolvCache' is Nothing.
-- * 'resolvQueryControls' is an empty set of overrides.
defaultResolvConf :: ResolvConf
defaultResolvConf = ResolvConf {
    resolvInfo          = RCFilePath "/etc/resolv.conf"
  , resolvTimeout       = 3 * 1000 * 1000
  , resolvRetry         = 3
  , resolvConcurrent    = False
  , resolvCache         = Nothing
  , resolvQueryControls = mempty
  , resolvGetTime       = getEpochTime
  , resolvTimeoutAction = timeout
  , resolvSolver        = udpTcpSolver
}
