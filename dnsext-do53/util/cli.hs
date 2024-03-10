{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import DNS.Do53.Internal
import DNS.Types
import Data.IORef
import Data.IP ()
import Data.List
import System.Environment

main :: IO ()
main = do
    args <- getArgs
    let (ats, doms') = partition ("@" `isPrefixOf`) args
        ips = read . drop 1 <$> ats
        doms = fromRepresentation <$> doms'
        domsN = length doms
        port = 53
        lim = 1024
        ris = (\ip -> defaultResolveInfo{rinfoIP = ip, rinfoPort = port}) <$> ips
    refs <- replicateM domsN (newIORef False)
    let targets = zip doms refs
    stdoutLock <- newMVar ()
    foldr1 race_ $ map (withServer stdoutLock lim targets) ris
  where
    withServer stdoutLock lim targets ri = withTCPResolver lim ri $ \resolv -> do
        foldr1 concurrently_ $ map (lookupAndPrint resolv stdoutLock) targets
    lookupAndPrint resolv stdoutLock (dom, ref) = do
        r <- resolv q mempty
        notyet <- atomicModifyIORef' ref $ \b -> (True, b)
        unless notyet $ withMVar stdoutLock $ \() -> print r
      where
        q = Question dom A IN
