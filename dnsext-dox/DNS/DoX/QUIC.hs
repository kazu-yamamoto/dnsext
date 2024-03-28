{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.QUIC where

import Codec.Serialise
import DNS.Do53.Internal
import DNS.Types.Decode
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import Network.QUIC
import Network.QUIC.Client
import Network.QUIC.Internal hiding (Recv, shared)

import DNS.DoX.Imports

quicPersistentResolver :: PersistentResolver
quicPersistentResolver ri@ResolveInfo{..} body = run cc $ \conn -> do
    body $ resolv conn ri
    rinfo <- getResumptionInfo conn
    when (isResumptionPossible rinfo) $ do
        let bs = BL.toStrict $ serialise rinfo
        ractionSaveResumption rinfoActions bs
  where
    cc = getQUICParams ri "doq"

quicResolver :: OneshotResolver
quicResolver ri q qctl = run cc $ \conn -> do
    resolv conn ri q qctl
  where
    cc = getQUICParams ri "doq"

resolv :: Connection -> ResolveInfo -> Resolver
resolv conn ri@ResolveInfo{..} q qctl = do
    strm <- stream conn
    ident <- ractionGenId rinfoActions
    let qry = encodeQuery ident q qctl
        tx = BS.length qry
    sendVC (sendStreamMany strm) qry
    shutdownStream strm
    (rx, bss) <- recvVC rinfoVCLimit $ recvStream strm
    now <- getTime
    case decodeChunks now bss of
        Left e -> return $ Left e
        Right msg -> case checkRespM q ident msg of -- fixme
            Nothing -> return $ Right $ toResult ri "doq" $ Reply msg tx rx
            Just err -> return $ Left err
  where
    getTime = ractionGetTime rinfoActions

getQUICParams :: ResolveInfo -> ByteString -> ClientConfig
getQUICParams ResolveInfo{..} alpn =
    defaultClientConfig
        { ccServerName = show rinfoIP
        , ccPortName = show rinfoPort
        , ccALPN = \_ -> return $ Just [alpn]
        , ccDebugLog = False
        , ccValidate = False
        , ccVersions = [Version1]
        , ccResumption = rinfo
        , ccUse0RTT = ractionUseEarlyData rinfoActions
        }
  where
    rinfo = case ractionResumptionInfo rinfoActions of
        Nothing -> defaultResumptionInfo
        Just r -> case deserialiseOrFail $ BL.fromStrict r of
            Left _ -> defaultResumptionInfo
            Right x -> x
