{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.HTTP3 where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.Types
import DNS.Types.Decode
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as C8
import Network.HTTP.Types
import Network.HTTP3.Client
import Network.QUIC
import qualified Network.QUIC.Client as QUIC
import qualified UnliftIO.Exception as E

import DNS.DoX.Common

http3Resolver :: Resolver
http3Resolver q si@ResolvInfo{..} = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        ident <- solvGenId
        client conn conf ident q si
  where
    cc = getQUICParams solvHostName solvPortNumber "h3"

client :: Connection -> Config -> Identifier -> Resolver
client conn conf ident q ResolvInfo{..} = run conn cliconf conf cli
  where
    wire = encodeQuery ident q solvQueryControls
    hdr = clientDoHHeaders wire
    req = requestBuilder methodPost "/dns-query" hdr $ BB.byteString wire
    cliconf = ClientConfig {
        scheme = "https"
      , authority = C8.pack solvHostName
      }
    cli sendRequest = sendRequest req $ \rsp -> do
        bs <- loop rsp ""
        now <- solvGetTime
        case decodeAt now bs of
            Left  e   -> E.throwIO e
            Right msg -> case checkRespM q ident msg of
                Nothing  -> return msg
                Just err -> E.throwIO err
      where
        loop rsp bs0 = do
            bs <- getResponseBodyChunk rsp
            if bs == "" then return bs0
                        else loop rsp (bs0 <> bs)
