{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.HTTP3 where

import DNS.Types.Decode
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as C8
import Network.HTTP.Types
import Network.HTTP3.Client
import Network.QUIC
import qualified Network.QUIC.Client as QUIC
import Network.Socket hiding (recvBuf)
import qualified UnliftIO.Exception as E

import DNS.DoX.Common

doh3 :: HostName -> PortNumber -> WireFormat -> IO ()
doh3 hostname port qry = QUIC.run cc $ \conn -> client conn hostname qry
  where
    cc = getQUICParams hostname port "h3"

client :: Connection -> HostName -> WireFormat -> IO ()
client conn hostname msg = E.bracket allocSimpleConfig freeSimpleConfig $ \conf -> run conn cliconf conf cli
  where
    hdr = clientDoHHeaders msg
    req = requestBuilder methodPost "/dns-query" hdr $ BB.byteString msg
    cliconf = ClientConfig {
        scheme = "https"
      , authority = C8.pack hostname
      }
    cli sendRequest = sendRequest req $ \rsp -> do
        --- print $ responseStatus rsp
        bs <- loop rsp ""
        print $ decode bs
      where
        loop rsp bs0 = do
            bs <- getResponseBodyChunk rsp
            if bs == "" then return bs0
                        else loop rsp (bs0 <> bs)
