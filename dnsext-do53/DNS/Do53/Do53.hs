{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.Do53.Do53 (
    resolve
  ) where

import Control.Concurrent.Async (async, waitAnyCancel)
import Control.Exception as E
import DNS.Types
import Network.Socket (Socket, close, openSocket, connect, getAddrInfo, AddrInfo(..), defaultHints, HostName, PortNumber, SocketType(..), AddrInfoFlag(..))
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

type Rslv0 = QueryControls -> (Socket -> IO DNSMessage)
           -> IO (Either DNSError DNSMessage)

type Rslv1 = Question
          -> Int -- Timeout
          -> Int -- Retry
          -> Rslv0

type TcpRslv = IO Identifier
            -> AddrInfo
            -> Question
            -> Int -- Timeout
            -> QueryControls
            -> IO DNSMessage

type UdpRslv = Int -- Retry
            -> (Socket -> IO DNSMessage)
            -> TcpRslv

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
resolve rlv dom typ qctls rcv
  | typ == AXFR   = return $ Left InvalidAXFRLookup
  | onlyOne       = resolveOne        (head nss) (head gens) q tm retry ctls rcv
  | concurrent    = resolveConcurrent nss        gens        q tm retry ctls rcv
  | otherwise     = resolveSequential nss        gens        q tm retry ctls rcv
  where
    q = Question dom typ classIN

    nss = serverAddrs rlv
    gens = genIds rlv

    onlyOne = length nss == 1
    conf = resolvConf rlv
    ctls    = qctls <> resolvQueryControls conf
    concurrent = resolvConcurrent conf
    tm         = resolvTimeout conf
    retry      = resolvRetry conf


resolveSequential :: [(HostName,PortNumber)] -> [IO Identifier] -> Rslv1
resolveSequential nss gs q tm retry ctls rcv = loop nss gs
  where
    loop [ai]     [gen] = resolveOne ai gen q tm retry ctls rcv
    loop (ai:ais) (gen:gens) = do
        eres <- resolveOne ai gen q tm retry ctls rcv
        case eres of
          Left  _ -> loop ais gens
          res     -> return res
    loop _  _     = error "resolveSequential:loop"

resolveConcurrent :: [(HostName,PortNumber)] -> [IO Identifier] -> Rslv1
resolveConcurrent nss gens q tm retry ctls rcv =
    raceAny $ zipWith run nss gens
  where
    raceAny ios = do
        asyncs <- mapM async ios
        snd <$> waitAnyCancel asyncs
    run ai gen = resolveOne ai gen q tm retry ctls rcv

resolveOne :: (HostName,PortNumber) -> IO Identifier -> Rslv1
resolveOne hp gen q tm retry ctls rcv = do
    ai <- makeAddrInfo hp
    E.try $ udpTcpResolve retry rcv gen ai q tm ctls

----------------------------------------------------------------

-- UDP attempts must use the same ID and accept delayed answers
-- but we use a fresh ID for each TCP lookup.
--
udpTcpResolve :: UdpRslv
udpTcpResolve retry rcv gen ai q tm ctls =
    udpResolve retry rcv gen ai q tm ctls `E.catch`
        \TCPFallback -> tcpResolve gen ai { addrSocketType = Stream } q tm ctls

----------------------------------------------------------------

ioErrorToDNSError :: AddrInfo -> String -> IOError -> IO DNSMessage
ioErrorToDNSError ai protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = protoName ++ "@" ++ show (addrAddress ai)
    aioe = annotateIOError ioe loc Nothing Nothing

----------------------------------------------------------------

open :: AddrInfo -> IO Socket
open ai = do
    sock <- openSocket ai
    connect sock $ addrAddress ai
    return sock

----------------------------------------------------------------

-- This throws DNSError or TCPFallback.
udpResolve :: UdpRslv
udpResolve retry rcv gen ai q tm ctls0 =
    E.handle (ioErrorToDNSError ai "udp") $
      bracket (open ai) close $ go ctls0
  where
    go ctls sock = do
      res <- perform ctls sock retry
      let fl = flags $ header res
          tc = trunCation fl
          rc = rcode fl
          eh = ednsHeader res
          cs = ednsEnabled FlagClear <> ctls
      if tc then E.throwIO TCPFallback
      else if rc == FormatErr && eh == NoEDNS && cs /= ctls
      then perform cs sock retry
      else return res

    perform _ _ 0 =  E.throwIO RetryLimitExceeded
    perform cs sock cnt = do
        ident <- gen
        let qry = encodeQuery ident q cs
        mres <- timeout tm $ do
            sendUDP sock qry
            getAns sock ident
        case mres of
           Nothing  -> perform cs sock (cnt - 1)
           Just res -> return res

    -- | Closed UDP ports are occasionally re-used for a new query, with
    -- the nameserver returning an unexpected answer to the wrong socket.
    -- Such answers should be simply dropped, with the client continuing
    -- to wait for the right answer, without resending the question.
    -- Note, this eliminates sequence mismatch as a UDP error condition,
    -- instead we'll time out if no matching answer arrives.
    --
    getAns sock ident = do
        res <- rcv sock
        if checkResp q ident res
        then return res
        else getAns sock ident

----------------------------------------------------------------

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.
-- This throws DNSError only.
tcpResolve :: TcpRslv
tcpResolve gen ai q tm ctls0 =
    E.handle (ioErrorToDNSError ai "tcp") $ do
        bracket (open ai) close $ go ctls0
  where
    go ctls sock = do
        let send = sendVC (sendTCP sock)
            recv = recvVC (recvTCP sock)
        res <- perform ctls send recv
        let fl = flags $ header res
            rc = rcode fl
            eh = ednsHeader res
            cs = ednsEnabled FlagClear <> ctls
        -- If we first tried with EDNS, retry without on FormatErr.
        if rc == FormatErr && eh == NoEDNS && cs /= ctls
        then perform cs send recv
        else return res

    perform cs send recv = do
        ident <- gen
        let qry = encodeQuery ident q cs
        mres <- timeout tm $ do
            _ <- send qry
            getAns recv ident
        case mres of
            Nothing  -> E.throwIO TimeoutExpired
            Just res -> return res

    getAns recv ident = do
        res <- recv
        case checkRespM q ident res of
            Nothing  -> return res
            Just err -> E.throwIO err

----------------------------------------------------------------

makeAddrInfo :: (HostName,PortNumber) -> IO AddrInfo
makeAddrInfo (nh,p) = do
    let hints = defaultHints {
            -- fixme passive
            addrFlags = [AI_ADDRCONFIG, AI_NUMERICHOST, AI_NUMERICSERV, AI_PASSIVE]
          , addrSocketType = Datagram
          }
    let np = show p
    head <$> getAddrInfo (Just hints) (Just nh) (Just np)
