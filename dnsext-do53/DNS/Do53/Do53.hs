{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Do53 (
    resolve
  , udpResolve
  , tcpResolve
  , Do(..)
  ) where

import Control.Concurrent.Async (async, waitAnyCancel)
import Control.Exception as E
import DNS.Types
import DNS.Types.Decode
-- import Network.Socket (close, openSocket, connect, getAddrInfo, AddrInfo(..), defaultHints, HostName, PortNumber, SocketType(..), AddrInfoFlag(..))
import Network.Socket (HostName, PortNumber, close)
import qualified Network.UDP as UDP
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Resolver
import DNS.Do53.Query

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

data Do = Do {
    doQuestion      :: Question
  , doHostName      :: HostName
  , doPortNumber    :: PortNumber
  , doTimeout       :: Int
  , doRetry         :: Int
  , doGenId         :: IO Identifier
  , doGetTime       :: IO EpochTime
  , doQueryControls :: QueryControls
  }

-- In lookup loop, we try UDP until we get a response.  If the response
-- is truncated, we try TCP once, with no further UDP retries.
--
-- For now, we optimize for low latency high-availability caches
-- (e.g.  running on a loopback interface), where TCP is cheap
-- enough.  We could attempt to complete the TCP lookup within the
-- original time budget of the truncated UDP query, by wrapping both
-- within a a single 'timeout' thereby staying within the original
-- time budget, but it seems saner to give TCP a full opportunity to
-- return results.  TCP latency after a truncated UDP reply will be
-- atypical.
--
-- Future improvements might also include support for TCP on the
-- initial query.
--
-- This function merges the query flag overrides from the resolver
-- configuration with any additional overrides from the caller.
--
resolve :: Resolver -> Domain -> TYPE -> QueryControls -> IO EpochTime
        -> IO DNSMessage
resolve rlv dom typ qctl0 getTime
  | typ == AXFR   = E.throwIO InvalidAXFRLookup
  | concurrent    = resolveConcurrent dos
  | otherwise     = resolveSequential dos
  where
    concurrent = resolvConcurrent $ resolvConf rlv
    dos = makeDos rlv dom typ qctl0 getTime

makeDos :: Resolver -> Domain -> TYPE -> QueryControls -> IO EpochTime -> [Do]
makeDos rlv dom typ qctl0 getTime = go hps0 gens0
  where
    conf = resolvConf rlv
    defaultDo = Do {
        doQuestion      = Question dom typ classIN
      , doHostName      = "127.0.0.1" -- to be overwitten
      , doPortNumber    = 53          -- to be overwitten
      , doTimeout       = resolvTimeout conf
      , doRetry         = resolvRetry conf
      , doGenId         = return 0    -- to be overwitten
      , doGetTime       = getTime
      , doQueryControls = qctl0 <> resolvQueryControls conf
      }
    hps0 = serverAddrs rlv
    gens0 = genIds rlv
    go ((h,p):hps) (gen:gens) = defaultDo { doHostName = h, doPortNumber = p, doGenId = gen } : go hps gens
    go _ _ = []

resolveSequential :: [Do] -> IO DNSMessage
resolveSequential dos0 = loop dos0
  where
    loop []       = error "resolveSequential:loop"
    loop [di]     = resolveOne di
    loop (di:dos) = do
        eres <- E.try $ resolveOne di
        case eres of
          Left (_ :: DNSError) -> loop dos
          Right res -> return res

resolveConcurrent :: [Do] -> IO DNSMessage
resolveConcurrent dos =
    raceAny $ map resolveOne dos
  where
    raceAny ios = do
        asyncs <- mapM async ios
        snd <$> waitAnyCancel asyncs

resolveOne :: Do -> IO DNSMessage
resolveOne = udpTcpResolve

----------------------------------------------------------------

data TCPFallback = TCPFallback deriving (Show, Typeable)
instance Exception TCPFallback

-- UDP attempts must use the same ID and accept delayed answers
-- but we use a fresh ID for each TCP lookup.
--
udpTcpResolve :: Do -> IO DNSMessage
udpTcpResolve di = udpResolve di `E.catch` \TCPFallback -> tcpResolve di

----------------------------------------------------------------

ioErrorToDNSError :: HostName -> String -> IOError -> IO DNSMessage
ioErrorToDNSError h protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = protoName ++ "@" ++ h
    aioe = annotateIOError ioe loc Nothing Nothing

----------------------------------------------------------------

-- This throws DNSError or TCPFallback.
udpResolve :: Do -> IO DNSMessage
udpResolve di@Do{..} =
    E.handle (ioErrorToDNSError doHostName "udp") $
      bracket open UDP.close $ \sock -> do
        let send = UDP.send sock
            recv = UDP.recv sock
        res <- solve send recv di
        let fl = flags $ header res
            tc = trunCation fl
            rc = rcode fl
            eh = ednsHeader res
            qctl = ednsEnabled FlagClear <> doQueryControls
        if tc then E.throwIO TCPFallback
        else if rc == FormatErr && eh == NoEDNS && qctl /= doQueryControls
        then solve send recv di
        else return res

  where
    open = UDP.clientSocket doHostName (show doPortNumber) True -- connected

----------------------------------------------------------------

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.
-- This throws DNSError only.
tcpResolve :: Do -> IO DNSMessage
tcpResolve di@Do{..} =
    E.handle (ioErrorToDNSError doHostName "tcp") $ do
      bracket (openTCP doHostName doPortNumber) close $ \sock -> do
        let send = sendVC $ sendTCP sock
            recv = recvVC $ recvTCP sock
        res <- solve send recv di
        let fl = flags $ header res
            rc = rcode fl
            eh = ednsHeader res
            qctl = ednsEnabled FlagClear <> doQueryControls
        -- If we first tried with EDNS, retry without on FormatErr.
        if rc == FormatErr && eh == NoEDNS && qctl /= doQueryControls
        then solve send recv di
        else return res

----------------------------------------------------------------

solve :: (ByteString -> IO ())
      -> IO ByteString
      -> Do
      -> IO DNSMessage
solve send recv Do{..} = go doRetry
  where
    go 0 = E.throwIO RetryLimitExceeded
    go cnt = do
        ident <- doGenId
        let qry = encodeQuery ident doQuestion doQueryControls
        mres <- timeout doTimeout $ do
            send qry
            getAnswer doQuestion ident recv doGetTime
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
