{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX (
    dot
  , doq
  , doh
  , doh3
  , google
  , cloudflare
  , adguard
  , mew
  , iij
  ) where

import Network.Socket
import DNS.Do53.Client
import DNS.Types

import DNS.DoX.Common
import qualified DNS.DoX.HTTP2 as DoH
import qualified DNS.DoX.HTTP3 as DoH3
import qualified DNS.DoX.QUIC  as DoQ
import qualified DNS.DoX.TLS   as DoT

----------------------------------------------------------------

dot :: HostName -> WireFormat -> IO ()
dot h q = DoT.dot h 853 q

doq :: HostName -> WireFormat -> IO ()
doq h q = DoQ.doq h 853 q

doh :: HostName -> WireFormat -> IO ()
doh h q = DoH.doh h 443 q

doh3 :: HostName -> WireFormat -> IO ()
doh3 h q = DoH3.doh3 h 443 q

----------------------------------------------------------------

google :: HostName
google = "8.8.8.8"

-- https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-wireformat/
cloudflare :: HostName
cloudflare = "1.1.1.1"

adguard :: HostName
adguard = "94.140.14.140"

----------------------------------------------------------------

iijQ :: Question
iijQ = Question "www.iij.ad.jp" A classIN

iij :: WireFormat
iij = encodeQuery 100 iijQ mempty
--iij = encodeQuery 100 iijQ (ednsEnabled FlagClear)

mewQ :: Question
mewQ = Question "www.mew.org" A classIN

mew :: WireFormat
mew = encodeQuery 100 mewQ mempty
