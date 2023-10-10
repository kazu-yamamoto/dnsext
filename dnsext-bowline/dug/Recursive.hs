{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Recursive (recursiveQeury) where

import DNS.Do53.Client (
    LookupConf (..),
    QueryControls,
    ResolvActions (..),
    Seeds (..),
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    Result (..),
    udpTcpResolver,
    withLookupConfAndResolver,
 )
import DNS.DoX.Stub
import qualified DNS.Log as Log
import DNS.SVCB
import DNS.Types (DNSError, Question (..))
import qualified DNS.Types as DNS
import Data.ByteString.Short (ShortByteString)
import Data.IP (IPv4, IPv6)
import Network.Socket (HostName, PortNumber)
import Text.Read (readMaybe)
import Data.Either

recursiveQeury
    :: [HostName]
    -> PortNumber
    -> ShortByteString
    -> Log.PutLines
    -> [DNS.ResolvActionsFlag]
    -> QueryControls
    -> HostName
    -> TYPE
    -> IO (Either DNSError Result)
recursiveQeury mserver port dox putLines raflags ctl domain typ | dox == "auto" = do
    conf <- getCustomConf mserver port ctl putLines raflags
    lookupDoX conf domain typ
recursiveQeury mserver port dox putLines raflags ctl domain typ = do
    conf <- getCustomConf mserver port ctl putLines raflags
    let lim = DNS.lconfLimit conf
        resolver = case makeResolver dox lim Nothing of
            Just r -> r
            Nothing ->
                let retry = DNS.lconfRetry conf
                 in udpTcpResolver retry lim
    withLookupConfAndResolver conf resolver $ \env -> do
        let q = Question (DNS.fromRepresentation domain) typ DNS.IN
        DNS.lookupRaw env q

getCustomConf
    :: [HostName]
    -> PortNumber
    -> QueryControls
    -> Log.PutLines
    -> [DNS.ResolvActionsFlag]
    -> IO LookupConf
getCustomConf mserver port ctl putLines raflags = case mserver of
    [] -> return conf
    hs -> do
        as <- concat <$> mapM toNumeric hs
        let aps = map (,port) as
        return $ conf{lconfSeeds = SeedsHostPorts aps}
  where
    conf =
        DNS.defaultLookupConf
            { lconfRetry = 2
            , lconfQueryControls = ctl
            , lconfConcurrent = True
            , lconfActions =
                DNS.defaultResolvActions
                    { ractionLog = putLines
                    , ractionFlags = raflags
                    }
            }

    toNumeric :: HostName -> IO [HostName]
    toNumeric sname | isNumeric sname = return [sname]
    toNumeric sname = DNS.withLookupConf DNS.defaultLookupConf $ \env -> do
        let dom = DNS.fromRepresentation sname
        eA <- fmap (fmap (show . DNS.a_ipv4)) <$> DNS.lookupA env dom
        eAAAA <- fmap (fmap (show . DNS.aaaa_ipv6)) <$> DNS.lookupAAAA env dom
        case rights [eA,eAAAA] of
          [] -> fail $ show eA
          hss -> return $ concat hss

isNumeric :: HostName -> Bool
isNumeric h = case readMaybe h :: Maybe IPv4 of
    Just _ -> True
    Nothing -> case readMaybe h :: Maybe IPv6 of
        Just _ -> True
        Nothing -> False
