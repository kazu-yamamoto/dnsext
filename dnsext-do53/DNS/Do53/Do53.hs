{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Do53 (
    udpTcpResolver
  , udpResolver
  , tcpResolver
  , defaultResolvConf
  , vcResolver
  , Send
  , Recv
  , checkRespM
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

-- | A resolver using UDP and TCP.
udpTcpResolver :: Resolver
udpTcpResolver q ri = udpResolver q ri `E.catch` \TCPFallback -> tcpResolver q ri

----------------------------------------------------------------

ioErrorToDNSError :: HostName -> String -> IOError -> IO DNSMessage
ioErrorToDNSError h protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = protoName ++ "@" ++ h
    aioe = annotateIOError ioe loc Nothing Nothing

----------------------------------------------------------------

-- | A resolver using UDP.
--   UDP attempts must use the same ID and accept delayed answers.
udpResolver :: Resolver
udpResolver q ResolvInfo{..} =
    E.handle (ioErrorToDNSError solvHostName "UDP") $ go solvQueryControls
  where
    -- Using only one socket and the same identifier.
    go qctl = bracket open UDP.close $ \sock -> do
        let send = UDP.send sock
            recv = UDP.recv sock
        ident <- solvGenId
        loop solvRetry ident qctl send recv

    loop 0 _ _ _ _ = E.throwIO RetryLimitExceeded
    loop cnt ident qctl0 send recv = do
        mres <- solve ident qctl0 send recv
        case mres of
          Nothing -> loop (cnt - 1) ident qctl0 send recv
          Just res -> do
              let fl = flags $ header res
                  tc = trunCation fl
                  rc = rcode fl
                  eh = ednsHeader res
                  qctl = ednsEnabled FlagClear <> qctl0
              when tc $ E.throwIO TCPFallback
              if rc == FormatErr && eh == NoEDNS && qctl /= qctl0 then
                  loop cnt ident qctl send recv
                else
                  return res

    solve ident qctl send recv = do
        let qry = encodeQuery ident q qctl
        solvTimeout $ do
            _ <- send qry
            getAnswer ident recv

    getAnswer ident recv = do
        bs <- recv `E.catch` \e -> E.throwIO $ NetworkFailure e
        now <- solvGetTime
        case decodeAt now bs of
            Left  e -> E.throwIO e
            Right msg
              | checkResp q ident msg -> return msg
              -- Just ignoring a wrong answer.
              | otherwise             -> getAnswer ident recv

    open = UDP.clientSocket solvHostName (show solvPortNumber) True -- connected

----------------------------------------------------------------

-- | A resolver using TCP.
tcpResolver :: Resolver
tcpResolver q ri@ResolvInfo{..} = vcResolver "TCP" perform q ri
  where
    -- Using a fresh connection
    perform solve = bracket open close $ \sock -> do
        let send = sendVC $ sendTCP sock
            recv = recvVC $ recvTCP sock
        solve send recv

    open = openTCP solvHostName solvPortNumber

type Send = ByteString -> IO ()
type Recv = IO ByteString

-- | Generic resolver for virtual circuit.
vcResolver :: String -> ((Send -> Recv -> IO DNSMessage) -> IO DNSMessage) -> Resolver
vcResolver proto perform q ResolvInfo{..} =
    E.handle (ioErrorToDNSError solvHostName proto) $ go solvQueryControls
  where
    go qctl0 = do
        res <- perform $ solve qctl0
        let fl = flags $ header res
            rc = rcode fl
            eh = ednsHeader res
            qctl = ednsEnabled FlagClear <> qctl0
        -- If we first tried with EDNS, retry without on FormatErr.
        if rc == FormatErr && eh == NoEDNS && qctl /= qctl0
        then perform $ solve qctl
        else return res

    solve qctl send recv = do
        -- Using a fresh identifier.
        ident <- solvGenId
        let qry = encodeQuery ident q qctl
        mres <- solvTimeout $ do
            _ <- send qry
            getAnswer ident recv
        case mres of
           Nothing  -> E.throwIO TimeoutExpired
           Just res -> return res

    getAnswer ident recv = do
        bs <- recv `E.catch` \e -> E.throwIO $ NetworkFailure e
        now <- solvGetTime
        case decodeAt now bs of
            Left  e   -> E.throwIO e
            Right msg -> case checkRespM q ident msg of
                Nothing  -> return msg
                Just err -> E.throwIO err

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
  , resolvResolver      = udpTcpResolver
}
