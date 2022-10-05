{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}

module DNS.IO.Transport (
    Resolver(..)
  , resolve
  ) where

import Control.Concurrent.Async (async, waitAnyCancel)
import Control.Exception as E
import DNS.Types
import qualified Data.ByteString.Char8 as C8
import qualified Data.List.NonEmpty as NE
import Network.Socket (AddrInfo(..), SockAddr(..), Family(AF_INET, AF_INET6), Socket, SocketType(Stream), close, socket, connect, defaultProtocol)
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

import DNS.IO.IO
import DNS.IO.Imports
import DNS.IO.Resolver.Types
import DNS.IO.Query

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

type TcpRslv = AddrInfo
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
  | isIllegal dom' = return $ Left IllegalDomain
  | typ == AXFR   = return $ Left InvalidAXFRLookup
  | onlyOne       = resolveOne        (head nss) (head gens) q tm retry ctls rcv
  | concurrent    = resolveConcurrent nss        gens        q tm retry ctls rcv
  | otherwise     = resolveSequential nss        gens        q tm retry ctls rcv
  where
    dom' = domainToByteString dom
    q = case C8.last dom' of
          '.' -> Question dom typ
          _   -> Question (dom <> ".") typ

    gens = NE.toList $ genIds rlv

    seed    = resolvseed rlv
    nss     = NE.toList $ nameservers seed
    onlyOne = length nss == 1
    ctls    = qctls <> resolvQueryControls (resolvconf $ resolvseed rlv)

    conf       = resolvconf seed
    concurrent = resolvConcurrent conf
    tm         = resolvTimeout conf
    retry      = resolvRetry conf


resolveSequential :: [AddrInfo] -> [IO Identifier] -> Rslv1
resolveSequential nss gs q tm retry ctls rcv = loop nss gs
  where
    loop [ai]     [gen] = resolveOne ai gen q tm retry ctls rcv
    loop (ai:ais) (gen:gens) = do
        eres <- resolveOne ai gen q tm retry ctls rcv
        case eres of
          Left  _ -> loop ais gens
          res     -> return res
    loop _  _     = error "resolveSequential:loop"

resolveConcurrent :: [AddrInfo] -> [IO Identifier] -> Rslv1
resolveConcurrent nss gens q tm retry ctls rcv = do
    asyncs <- mapM mkAsync $ zip nss gens
    snd <$> waitAnyCancel asyncs
  where
    mkAsync (ai,gen) = async $ resolveOne ai gen q tm retry ctls rcv

resolveOne :: AddrInfo -> IO Identifier -> Rslv1
resolveOne ai gen q tm retry ctls rcv =
    E.try $ udpTcpLookup gen retry rcv ai q tm ctls

----------------------------------------------------------------

-- UDP attempts must use the same ID and accept delayed answers
-- but we use a fresh ID for each TCP lookup.
--
udpTcpLookup :: IO Identifier -> UdpRslv
udpTcpLookup gen retry rcv ai q tm ctls = do
    ident <- gen
    udpLookup ident retry rcv ai q tm ctls `E.catch`
            \TCPFallback -> tcpLookup gen ai q tm ctls

----------------------------------------------------------------

ioErrorToDNSError :: AddrInfo -> String -> IOError -> IO DNSMessage
ioErrorToDNSError ai protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = protoName ++ "@" ++ show (addrAddress ai)
    aioe = annotateIOError ioe loc Nothing Nothing

----------------------------------------------------------------

udpOpen :: AddrInfo -> IO Socket
udpOpen ai = do
    sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
    connect sock (addrAddress ai)
    return sock

-- This throws DNSError or TCPFallback.
udpLookup :: Identifier -> UdpRslv
udpLookup ident retry rcv ai q tm ctls = do
    let qry = encodeQuery ident q ctls
    E.handle (ioErrorToDNSError ai "udp") $
      bracket (udpOpen ai) close (loop qry ctls 0 RetryLimitExceeded)
  where
    loop qry lctls cnt err sock
      | cnt == retry = E.throwIO err
      | otherwise    = do
          mres <- timeout tm (send sock qry >> getAns sock)
          case mres of
              Nothing  -> loop qry lctls (cnt + 1) RetryLimitExceeded sock
              Just res -> do
                      let fl = flags $ header res
                          tc = trunCation fl
                          rc = rcode fl
                          eh = ednsHeader res
                          cs = ednsEnabled FlagClear <> lctls
                      if tc then E.throwIO TCPFallback
                      else if rc == FormatErr && eh == NoEDNS && cs /= lctls
                      then let qry' = encodeQuery ident q cs
                            in loop qry' cs cnt RetryLimitExceeded sock
                      else return res

    -- | Closed UDP ports are occasionally re-used for a new query, with
    -- the nameserver returning an unexpected answer to the wrong socket.
    -- Such answers should be simply dropped, with the client continuing
    -- to wait for the right answer, without resending the question.
    -- Note, this eliminates sequence mismatch as a UDP error condition,
    -- instead we'll time out if no matching answer arrives.
    --
    getAns sock = do
        resp <- rcv sock
        if checkResp q ident resp
        then return resp
        else getAns sock

----------------------------------------------------------------

-- Create a TCP socket with the given socket address.
tcpOpen :: SockAddr -> IO Socket
tcpOpen peer = case peer of
    SockAddrInet{}  -> socket AF_INET  Stream defaultProtocol
    SockAddrInet6{} -> socket AF_INET6 Stream defaultProtocol
    _               -> E.throwIO ServerFailure

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.
-- This throws DNSError only.
tcpLookup :: IO Identifier -> TcpRslv
tcpLookup gen ai q tm ctls =
    E.handle (ioErrorToDNSError ai "tcp") $ do
        res <- bracket (tcpOpen addr) close (perform ctls)
        let rc = rcode $ flags $ header res
            eh = ednsHeader res
            cs = ednsEnabled FlagClear <> ctls
        -- If we first tried with EDNS, retry without on FormatErr.
        if rc == FormatErr && eh == NoEDNS && cs /= ctls
        then bracket (tcpOpen addr) close (perform cs)
        else return res
  where
    addr = addrAddress ai
    perform cs vc = do
        ident <- gen
        let qry = encodeQuery ident q cs
        mres <- timeout tm $ do
            connect vc addr
            sendVC vc qry
            receiveVC vc
        case mres of
            Nothing  -> E.throwIO TimeoutExpired
            Just res -> maybe (return res) E.throwIO (checkRespM q ident res)

----------------------------------------------------------------

badLength :: ByteString -> Bool
badLength dom
    | C8.null dom        = True
    | C8.last dom == '.' = C8.length dom > 254
    | otherwise          = C8.length dom > 253

isIllegal :: ByteString -> Bool
isIllegal dom
  | badLength dom               = True
  | '.' `C8.notElem` dom        = True
  | ':' `C8.elem` dom           = True
  | '/' `C8.elem` dom           = True
  | any (\x -> C8.length x > 63)
        (C8.split '.' dom)      = True
  | otherwise                   = False
