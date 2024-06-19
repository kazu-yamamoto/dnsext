{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module DNS.Do53.Do53 (
    udpTcpResolver,
    udpResolver,
    tcpResolver,
    vcResolver,
    checkRespM,
    nameTag,
    queryTag,
    fromIOException,
)
where

import Control.Exception as E
import qualified Data.ByteString as BS
import Network.Socket
import qualified Network.UDP as UDP
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)

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

-- | A resolver using UDP and TCP.
udpTcpResolver :: OneshotResolver
udpTcpResolver ri q qctl = do
    er <- udpResolver ri q qctl
    case er of
        r@(Right res) -> do
            let tc = trunCation $ flags $ replyDNSMessage res
            if tc
                then tcpResolver ri q qctl
                else return r
        e@(Left _) -> return e

----------------------------------------------------------------

fromIOException :: String -> E.IOException -> DNSError
fromIOException tag ioe = NetworkFailure aioe
  where
    aioe = annotateIOError ioe tag Nothing Nothing

nameTag :: ResolveInfo -> String -> String
nameTag ResolveInfo{..} proto = show rinfoIP ++ "#" ++ show rinfoPort ++ "/" ++ proto

queryTag :: Question -> String -> String
queryTag Question{..} tag = tag'
  where
    ~tag' =
        "    query "
            ++ show qname
            ++ " "
            ++ show qtype
            ++ " to "
            ++ tag

analyzeReply :: Reply -> QueryControls -> Maybe QueryControls
analyzeReply rply qctl0
    | rc == FormatErr && eh == NoEDNS && qctl /= qctl0 = Just qctl
    | otherwise = Nothing
  where
    ans = replyDNSMessage rply
    rc = rcode ans
    eh = ednsHeader ans
    qctl = ednsEnabled FlagClear <> qctl0

----------------------------------------------------------------

-- | A resolver using UDP.
--   UDP attempts must use the same ID and accept delayed answers.
udpResolver :: OneshotResolver
udpResolver ri@ResolveInfo{rinfoActions=ResolveActions{..},..} q _qctl = do
    ractionLog Log.DEMO Nothing [qtag]
    ex <- E.try $ go _qctl
    case ex of
        Right r -> return r
        Left se
            | Just (e :: DNSError) <- fromException se -> return $ Left e
            | Just (e :: E.IOException) <- fromException se -> do
                return $ Left $ fromIOException qtag e
            | otherwise -> return $ Left $ BadThing (show se)
  where
    name = nameTag ri "UDP"
    ~qtag = queryTag q name
    -- Using only one socket and the same identifier.
    go qctl = bracket open UDP.close $ \sock -> do
        ractionSetSockOpt $ UDP.udpSocket sock
        let send = UDP.send sock
            recv = UDP.recv sock
        ident <- ractionGenId
        loop rinfoUDPRetry ident qctl send recv

    loop 0 _ _ _ _ = return $ Left RetryLimitExceeded
    loop cnt ident qctl0 send recv = do
        mrply <- sendQueryRecvAnswer ident qctl0 send recv
        case mrply of
            Nothing -> loop (cnt - 1) ident qctl0 send recv
            Just rply -> do
                let mqctl = analyzeReply rply qctl0
                case mqctl of
                    Nothing -> return $ Right $ rply
                    Just qctl -> loop cnt ident qctl send recv

    sendQueryRecvAnswer ident qctl send recv = do
        let qry = encodeQuery ident q qctl
        timeout ractionTimeoutTime $ do
            _ <- send qry
            let tx = BS.length qry
            recvAnswer ident recv tx

    recvAnswer ident recv tx = do
        ans <- recv
        now <- ractionGetTime
        case decodeAt now ans of
            Left e -> do
                ractionLog Log.DEBUG Nothing $
                    let showHex8 w
                            | w >= 16 = showHex w
                            | otherwise = ('0' :) . showHex w
                        dumpBS = ("\"" ++) . (++ "\"") . foldr (\w s -> "\\x" ++ showHex8 w s) "" . BS.unpack
                     in ["udpResolver.recvAnswer: decodeAt Left: ", show rinfoIP ++ ", ", dumpBS ans]
                E.throwIO e
            Right msg
                | checkResp q ident msg -> do
                    let rx = BS.length ans
                    return $ Reply name msg tx rx
                -- Just ignoring a wrong answer.
                | otherwise -> do
                    ractionLog Log.DEBUG Nothing $
                        ["udpResolver.recvAnswer: checkResp error: ", show rinfoIP, ", ", show msg]
                    recvAnswer ident recv tx

    open = UDP.clientSocket (show rinfoIP) (show rinfoPort) True -- connected

----------------------------------------------------------------

-- | A resolver using TCP.
tcpResolver :: OneshotResolver
tcpResolver ri@ResolveInfo{..} q qctl =
    -- Using a fresh connection
    bracket open close $ \sock -> do
        ractionSetSockOpt rinfoActions sock
        let send = sendVC $ sendTCP sock
            recv = recvVC rinfoVCLimit $ recvTCP sock
        vcResolver "TCP" send recv ri q qctl
  where
    open = openTCP rinfoIP rinfoPort

-- | Generic resolver for virtual circuit.
vcResolver :: String -> Send -> RecvMany -> OneshotResolver
vcResolver proto send recv ri@ResolveInfo{rinfoActions=ResolveActions{..}} q _qctl = do
    ractionLog Log.DEMO Nothing [qtag]
    ex <- E.try $ go _qctl
    case ex of
        Right r -> return r
        Left se
            | Just (e :: DNSError) <- fromException se -> return $ Left e
            | Just (e :: E.IOException) <- fromException se -> do
                return $ Left $ fromIOException qtag e
            | otherwise -> return $ Left $ BadThing (show se)
  where
    name = nameTag ri proto
    ~qtag = queryTag q name
    go qctl0 = do
        erply <- sendQueryRecvAnswer qctl0
        case erply of
            Left e -> return $ Left e
            Right rply -> do
                let mqctl = analyzeReply rply qctl0
                case mqctl of
                    Nothing -> return $ Right rply
                    Just qctl -> do
                        erply' <- sendQueryRecvAnswer qctl
                        case erply' of
                            Left e' -> return $ Left e'
                            Right rply' -> return $ Right rply'

    sendQueryRecvAnswer qctl = do
        -- Using a fresh identifier.
        ident <- ractionGenId
        let qry = encodeQuery ident q qctl
        mres <- timeout ractionTimeoutTime $ do
            _ <- send qry
            let tx = BS.length qry
            recvAnswer ident tx
        case mres of
            Nothing -> return $ Left TimeoutExpired
            Just res -> return $ Right res

    recvAnswer ident tx = do
        (rx, bss) <- recv
        now <- ractionGetTime
        case decodeChunks now bss of
            Left e -> E.throwIO e
            Right msg -> case checkRespM q ident msg of
                Nothing -> return $ Reply name msg tx rx
                Just err -> E.throwIO err
