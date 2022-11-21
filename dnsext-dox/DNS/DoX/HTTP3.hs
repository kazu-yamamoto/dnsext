{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.HTTP3 where

import DNS.Types.Decode
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import qualified Data.ByteString.Char8 as C8
import Network.HTTP.Types
import qualified Network.HTTP3.Client as H3
import Network.QUIC
import Network.QUIC.Client
import Network.Socket hiding (recvBuf)
import qualified UnliftIO.Exception as E

import DNS.DoX.Common

doh3 :: HostName -> PortNumber -> WireFormat -> IO ()
doh3 hostname port qry = run cc $ \conn -> client conn hostname qry
  where
    cc = getQUICParams hostname port "h3"

client :: Connection -> HostName -> ByteString -> IO ()
client conn hostname msg = E.bracket H3.allocSimpleConfig H3.freeSimpleConfig $ \conf -> H3.run conn cliconf conf cli
  where
    req = H3.requestBuilder methodPost "/dns-query" clientDoHHeaders $ BB.byteString msg
    cliconf = H3.ClientConfig {
        H3.scheme = "https"
      , H3.authority = C8.pack hostname
      }
    cli sendRequest = sendRequest req $ \rsp -> do
        bs <- H3.getResponseBodyChunk rsp
        print $ decode bs
