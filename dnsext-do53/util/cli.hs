{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Concurrent
import Control.Concurrent.Async
import DNS.Do53.Internal
import DNS.Types
import Data.IP ()
import System.Environment

main :: IO ()
main = do
    atip : doms <- getArgs
    let ip = read $ drop 1 atip
        port = 53
        lim = 1024
    withTCPResolver ip port lim defaultResolveActions $ \resolv -> do
        var <- newMVar ()
        foldr1 concurrently_ $ map (go resolv var) doms
  where
    go resolv var dom = do
        r <- resolv q mempty
        withMVar var $ \() -> print r
      where
        q = Question (fromRepresentation (dom :: String)) A IN
