-- % sudo -u unbound dump <sock_path>
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Main where

import Control.Concurrent (forkIO)
import Control.Monad (forever, void)
import Network.Socket
import System.Environment (getArgs)
import Text.Pretty.Simple (pPrint)

import DNS.SEC (addResourceDataForDNSSEC)
import DNS.SVCB (addResourceDataForSVCB)
import DNS.TAP.FastStream (Config (..), reader)
import DNS.TAP.Schema (decodeDnstap)
import DNS.Types (runInitIO)

----------------------------------------------------------------

main :: IO ()
main = do
    [path] <- getArgs
    runInitIO $ do
        addResourceDataForDNSSEC
        addResourceDataForSVCB
    lsock <- socket AF_UNIX Stream defaultProtocol
    bind lsock $ SockAddrUnix path
    listen lsock 10
    loop lsock
  where
    loop lsock = forever $ do
        (sock, _) <- accept lsock
        let conf = Config True True
        void $ forkIO $ reader sock conf (pPrint . decodeDnstap)
