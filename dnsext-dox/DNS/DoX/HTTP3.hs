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
import qualified Network.QUIC.Client as QUIC
import qualified UnliftIO.Exception as E

import DNS.DoX.Common

http3Solver :: Solver
http3Solver si@SolvInfo{..} = QUIC.run cc $ \conn ->
    E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> do
        ident <- solvGenId
        run conn cliconf conf $ client ident si
  where
    cc = getQUICParams solvHostName solvPortNumber "h3"
    cliconf = ClientConfig {
        scheme = "https"
      , authority = C8.pack solvHostName
      }

client :: Identifier -> SolvInfo -> Client DNSMessage
client ident SolvInfo{..} = cli
  where
    wire = encodeQuery ident solvQuestion solvQueryControls
    hdr = clientDoHHeaders wire
    req = requestBuilder methodPost "/dns-query" hdr $ BB.byteString wire
    cli sendRequest = sendRequest req $ \rsp -> do
        bs <- loop rsp ""
        now <- solvGetTime
        case decodeAt now bs of
            Left  e   -> E.throwIO e
            Right msg -> case checkRespM solvQuestion ident msg of
                Nothing  -> return msg
                Just err -> E.throwIO err
      where
        loop rsp bs0 = do
            bs <- getResponseBodyChunk rsp
            if bs == "" then return bs0
                        else loop rsp (bs0 <> bs)
