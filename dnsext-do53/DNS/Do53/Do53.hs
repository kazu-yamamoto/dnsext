{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Do53 (
    udpTcpResolver,
    udpResolver,
    tcpResolver,
    vcResolver,
    checkRespM,
    toResult,
    lazyTag,
)
where

import Control.Exception as E
import qualified Data.ByteString as BS
import Network.Socket
import qualified Network.UDP as UDP
import System.IO.Error (annotateIOError)

import DNS.Do53.IO
import DNS.Do53.Imports
import DNS.Do53.Query
import DNS.Do53.Types
import qualified DNS.Log as Log
import DNS.Types
import DNS.Types.Decode

-- | Check response for a matching identifier and question.  If we ever do
-- pipelined TCP, we'll need to handle out of order responses.  See:
-- https://tools.ietf.org/html/rfc7766#section-7
checkResp :: Question -> Identifier -> DNSMessage -> Bool
checkResp q seqno = isNothing . checkRespM q seqno

-- When the response 'RCODE' is 'FormatErr', the server did not understand our
-- query packet, and so is not expected to return a matching question.
--
checkRespM :: Question -> Identifier -> DNSMessage -> Maybe DNSError
checkRespM q seqno resp
    | identifier resp /= seqno = Just SequenceNumberMismatch
    | FormatErr <- rcode resp
    , [] <- question resp =
        Nothing
    | [q] /= question resp = Just QuestionMismatch
    | otherwise = Nothing

----------------------------------------------------------------

data TCPFallback = TCPFallback deriving (Show, Typeable)

instance Exception TCPFallback

-- | A resolver using UDP and TCP.
udpTcpResolver :: UDPRetry -> VCLimit -> Resolver
udpTcpResolver retry lim ri q qctl =
    udpResolver retry ri q qctl `E.catch` \TCPFallback -> tcpResolver lim ri q qctl

----------------------------------------------------------------

throwFromIOError :: Question -> ResolveInfo -> String -> IOError -> IO a
throwFromIOError q ResolveInfo{..} protoName ioe = throwIO $ NetworkFailure aioe
  where
    loc = show q ++ ": " ++ protoName ++ show rinfoPort ++ "@" ++ show rinfoIP
    aioe = annotateIOError ioe loc Nothing Nothing

lazyTag :: ResolveInfo -> Question -> String -> String
lazyTag ResolveInfo{..} Question{..} proto = tag
  where
    ~tag =
        "    query "
            ++ show qname
            ++ " "
            ++ show qtype
            ++ " to "
            ++ show rinfoIP
            ++ "#"
            ++ show rinfoPort
            ++ "/"
            ++ proto

analyzeReply :: Reply -> QueryControls -> (Maybe QueryControls, Bool)
analyzeReply rply qctl0
    | rc == FormatErr && eh == NoEDNS && qctl /= qctl0 = (Just qctl, tc)
    | otherwise = (Nothing, tc)
  where
    ans = replyDNSMessage rply
    fl = flags ans
    tc = trunCation fl
    rc = rcode ans
    eh = ednsHeader ans
    qctl = ednsEnabled FlagClear <> qctl0

----------------------------------------------------------------

-- | A resolver using UDP.
--   UDP attempts must use the same ID and accept delayed answers.
udpResolver :: UDPRetry -> Resolver
udpResolver retry ri@ResolveInfo{..} q _qctl = do
    ractionLog rinfoActions Log.DEMO Nothing [tag]
    E.handle (throwFromIOError q ri "UDP") $ go _qctl
  where
    ~tag = lazyTag ri q "UDP"
    -- Using only one socket and the same identifier.
    go qctl = bracket open UDP.close $ \sock -> do
        ractionSetSockOpt rinfoActions $ UDP.udpSocket sock
        let send = UDP.send sock
            recv = UDP.recv sock
        ident <- ractionGenId rinfoActions
        loop retry ident qctl send recv

    loop 0 _ _ _ _ = E.throwIO RetryLimitExceeded
    loop cnt ident qctl0 send recv = do
        mrply <- sendQueryRecvAnswer ident qctl0 send recv
        case mrply of
            Nothing -> loop (cnt - 1) ident qctl0 send recv
            Just rply -> do
                let (mqctl, tc) = analyzeReply rply qctl0
                when tc $ E.throwIO TCPFallback
                case mqctl of
                    Nothing -> return $ toResult ri "UDP" rply
                    Just qctl -> loop cnt ident qctl send recv

    sendQueryRecvAnswer ident qctl send recv = do
        let qry = encodeQuery ident q qctl
        ractionTimeout rinfoActions $ do
            _ <- send qry
            let tx = BS.length qry
            recvAnswer ident recv tx

    recvAnswer ident recv tx = do
        ans <- recv `E.catch` throwFromIOError q ri "UDP"
        now <- ractionGetTime rinfoActions
        case decodeAt now ans of
            Left e -> do
                ractionLog rinfoActions Log.DEBUG Nothing $
                    let showHex8 w
                            | w >= 16 = showHex w
                            | otherwise = ('0' :) . showHex w
                        dumpBS = ("\"" ++) . (++ "\"") . foldr (\w s -> "\\x" ++ showHex8 w s) "" . BS.unpack
                     in ["udpResolver.recvAnswer: decodeAt Left: ", show rinfoIP ++ ", ", dumpBS ans]
                E.throwIO e
            Right msg
                | checkResp q ident msg -> do
                    let rx = BS.length ans
                    return $ Reply msg tx rx
                -- Just ignoring a wrong answer.
                | otherwise -> do
                    ractionLog rinfoActions Log.DEBUG Nothing $
                        ["udpResolver.recvAnswer: checkResp error: ", show rinfoIP, ", ", show msg]
                    recvAnswer ident recv tx

    open = UDP.clientSocket (show rinfoIP) (show rinfoPort) True -- connected

----------------------------------------------------------------

-- | A resolver using TCP.
tcpResolver :: VCLimit -> Resolver
tcpResolver lim ri@ResolveInfo{..} q qctl =
    -- Using a fresh connection
    bracket open close $ \sock -> do
        ractionSetSockOpt rinfoActions sock
        let send = sendVC $ sendTCP sock
            recv = recvVC lim $ recvTCP sock
        vcResolver "TCP" send recv ri q qctl
  where
    open = openTCP rinfoIP rinfoPort

-- | Generic resolver for virtual circuit.
vcResolver :: String -> Send -> RecvMany -> Resolver
vcResolver proto send recv ri@ResolveInfo{..} q _qctl = do
    ractionLog rinfoActions Log.DEMO Nothing [tag]
    E.handle (throwFromIOError q ri proto) $ go _qctl
  where
    ~tag = lazyTag ri q proto
    go qctl0 = do
        rply <- sendQueryRecvAnswer qctl0
        let (mqctl, _) = analyzeReply rply qctl0
        case mqctl of
            Nothing -> return $ toResult ri proto rply
            Just qctl -> toResult ri proto <$> sendQueryRecvAnswer qctl

    sendQueryRecvAnswer qctl = do
        -- Using a fresh identifier.
        ident <- ractionGenId rinfoActions
        let qry = encodeQuery ident q qctl
        mres <- ractionTimeout rinfoActions $ do
            _ <- send qry
            let tx = BS.length qry
            recvAnswer ident tx
        case mres of
            Nothing -> E.throwIO TimeoutExpired
            Just res -> return res

    recvAnswer ident tx = do
        (rx, bss) <- recv `E.catch` throwFromIOError q ri proto
        now <- ractionGetTime rinfoActions
        case decodeChunks now bss of
            Left e -> E.throwIO e
            Right msg -> case checkRespM q ident msg of
                Nothing -> return $ Reply msg tx rx
                Just err -> E.throwIO err

toResult :: ResolveInfo -> String -> Reply -> Result
toResult ResolveInfo{..} tag rply =
    Result
        { resultIP = rinfoIP
        , resultPort = rinfoPort
        , resultTag = tag
        , resultReply = rply
        }
