{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Do53.Do53 (
    resolve
  , udpResolve
  , tcpResolve
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

data TCPFallback = TCPFallback deriving (Show, Typeable)
instance Exception TCPFallback

type Rslv0 = QueryControls
          -> IO EpochTime
          -> IO (Either DNSError DNSMessage)

type Rslv1 = Question
          -> Int -- Timeout
          -> Int -- Retry
          -> Rslv0

type Rslv =  (HostName,PortNumber)
          -> IO Identifier
          -> Question
          -> Int -- Timeout
          -> Int -- Retry
          -> QueryControls
          -> IO EpochTime
          -> IO DNSMessage

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
resolve :: Resolver -> Domain -> TYPE -> Rslv0
resolve rlv dom typ qctl0 getTime
  | typ == AXFR   = return $ Left InvalidAXFRLookup
  | onlyOne       = resolveOne        (head nss) (head gens) q tm retry qctl getTime
  | concurrent    = resolveConcurrent nss        gens        q tm retry qctl getTime
  | otherwise     = resolveSequential nss        gens        q tm retry qctl getTime
  where
    q = Question dom typ classIN

    nss = serverAddrs rlv
    gens = genIds rlv

    onlyOne = length nss == 1
    conf = resolvConf rlv
    qctl    = qctl0 <> resolvQueryControls conf
    concurrent = resolvConcurrent conf
    tm         = resolvTimeout conf
    retry      = resolvRetry conf

resolveSequential :: [(HostName,PortNumber)] -> [IO Identifier] -> Rslv1
resolveSequential nss gs q tm retry qctl getTime = loop nss gs
  where
    loop [ai]     [gen] = resolveOne ai gen q tm retry qctl getTime
    loop (ai:ais) (gen:gens) = do
        eres <- resolveOne ai gen q tm retry qctl getTime
        case eres of
          Left  _ -> loop ais gens
          res     -> return res
    loop _  _     = error "resolveSequential:loop"

resolveConcurrent :: [(HostName,PortNumber)] -> [IO Identifier] -> Rslv1
resolveConcurrent nss gens q tm retry qctl getTime =
    raceAny $ zipWith run nss gens
  where
    raceAny ios = do
        asyncs <- mapM async ios
        snd <$> waitAnyCancel asyncs
    run ai gen = resolveOne ai gen q tm retry qctl getTime

resolveOne :: (HostName,PortNumber) -> IO Identifier -> Rslv1
resolveOne hp gen q tm retry qctl getTime = do
    E.try $ udpTcpResolve hp gen q tm retry qctl getTime

----------------------------------------------------------------

-- UDP attempts must use the same ID and accept delayed answers
-- but we use a fresh ID for each TCP lookup.
--
udpTcpResolve :: Rslv
udpTcpResolve hp gen q tm retry qctl getTime =
    udpResolve hp gen q tm retry qctl getTime `E.catch`
        \TCPFallback -> tcpResolve hp gen q tm retry qctl getTime

----------------------------------------------------------------

ioErrorToDNSError :: (HostName,PortNumber) -> String -> IOError -> IO DNSMessage
ioErrorToDNSError (h,_) protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = protoName ++ "@" ++ h
    aioe = annotateIOError ioe loc Nothing Nothing

----------------------------------------------------------------

-- This throws DNSError or TCPFallback.
udpResolve :: Rslv
udpResolve hp gen q tm retry qctl0 getTime =
    E.handle (ioErrorToDNSError hp "udp") $
      bracket (open hp) UDP.close $ \sock -> do
        let send = UDP.send sock
            recv = UDP.recv sock
        res <- solve send recv gen q tm retry qctl0 getTime
        let fl = flags $ header res
            tc = trunCation fl
            rc = rcode fl
            eh = ednsHeader res
            qctl = ednsEnabled FlagClear <> qctl0
        if tc then E.throwIO TCPFallback
        else if rc == FormatErr && eh == NoEDNS && qctl /= qctl0
        then solve send recv gen q tm retry qctl getTime
        else return res

  where
    open (h,p) = UDP.clientSocket h (show p) True -- connected

----------------------------------------------------------------

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.
-- This throws DNSError only.
tcpResolve :: Rslv
tcpResolve hp@(h,p) gen q tm _retry qctl0 getTime =
    E.handle (ioErrorToDNSError hp "tcp") $ do
      bracket (openTCP h p) close $ \sock -> do
        let send = sendVC $ sendTCP sock
            recv = recvVC $ recvTCP sock
        res <- solve send recv gen q tm 1 qctl0 getTime
        let fl = flags $ header res
            rc = rcode fl
            eh = ednsHeader res
            qctl = ednsEnabled FlagClear <> qctl0
        -- If we first tried with EDNS, retry without on FormatErr.
        if rc == FormatErr && eh == NoEDNS && qctl /= qctl0
        then solve send recv gen q tm 1 qctl getTime
        else return res

----------------------------------------------------------------

solve :: (ByteString -> IO ())
      -> IO ByteString
      -> IO Identifier
      -> Question
      -> Int -- Timeout
      -> Int -- Retry
      -> QueryControls
      -> IO EpochTime
      -> IO DNSMessage
solve send recv gen q tm cnt0 qctl getTime = go cnt0
  where
    go 0 = E.throwIO RetryLimitExceeded
    go cnt = do
        ident <- gen
        let qry = encodeQuery ident q qctl
        mres <- timeout tm $ do
            send qry
            getAnswer q ident recv getTime
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
