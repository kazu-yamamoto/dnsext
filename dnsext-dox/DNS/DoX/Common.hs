{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.Common where

import DNS.Types
import Network.HTTP.Types

iij :: Question
iij = Question "www.iij.ad.jp" A classIN

mew :: Question
mew = Question "www.mew.org" A classIN

clientDoHHeaders :: RequestHeaders
clientDoHHeaders = [
    (hUserAgent,   "HaskellQuic/0.0.0")
  , (hContentType, "application/dns-message")
  , (hAccept,      "application/dns-message")
  ]
