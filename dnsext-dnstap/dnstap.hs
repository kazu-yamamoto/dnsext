{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Main where

import Control.Concurrent
import Control.Monad
import Network.Socket
import Text.Pretty.Simple

import DNS.Types (runInitIO)
import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (addResourceDataForSVCB)
import DNS.TAP.FastStream
import DNS.TAP.Schema

----------------------------------------------------------------

main :: IO ()
main = do
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    lsock <- socket AF_UNIX Stream defaultProtocol
    bind lsock $ SockAddrUnix "/opt/local/etc/unbound/tmp/unbound.sock"
    listen lsock 10
    loop lsock
  where
    loop lsock = forever $ do
        (sock, _) <- accept lsock
        ctx <- newReaderContext sock $ Config True True
        void $ forkIO $ reader ctx (pPrint . decodeDnstap)
