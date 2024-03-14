{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Recursive (recursiveQeury) where

import DNS.Do53.Client (
    LookupConf (..),
    QueryControls,
    ResolveActions (..),
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
import DNS.Types (DNSError, Question (..))
import qualified DNS.Types as DNS
import Data.ByteString.Short (ShortByteString)
import Data.Either
import Data.IP (IPv4, IPv6)
import Data.String
import Network.Socket (HostName, PortNumber)
import Text.Read (readMaybe)

recursiveQeury
    :: [HostName]
    -> PortNumber
    -> ShortByteString
    -> Log.PutLines
    -> [DNS.ResolveActionsFlag]
    -> (Question, QueryControls)
    -> IO (Either DNSError Result)
recursiveQeury mserver port dox putLines raflags (q, ctl) | dox == "auto" = do
    conf <- getCustomConf mserver port ctl putLines raflags
    withLookupConfAndResolver conf udpTcpResolver $ \lenv ->
        lookupRawDoX lenv q
recursiveQeury mserver port dox putLines raflags (q, ctl) = do
    conf <- getCustomConf mserver port ctl putLines raflags
    let resolver = case makeOneshotResolver dox of
            Just r -> r
            Nothing -> udpTcpResolver
    withLookupConfAndResolver conf resolver $ \lenv ->
        DNS.lookupRaw lenv q

getCustomConf
    :: [HostName]
    -> PortNumber
    -> QueryControls
    -> Log.PutLines
    -> [DNS.ResolveActionsFlag]
    -> IO LookupConf
getCustomConf mserver port ctl putLines raflags = case mserver of
    [] -> return conf
    hs -> do
        as <- concat <$> mapM toNumeric hs
        let aps = map (\h -> (fromString h, port)) as
        return $ conf{lconfSeeds = SeedsAddrPorts aps}
  where
    conf =
        DNS.defaultLookupConf
            { lconfUDPRetry = 2
            , lconfQueryControls = ctl
            , lconfConcurrent = True
            , lconfActions =
                DNS.defaultResolveActions
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
        case rights [eA, eAAAA] of
            [] -> fail $ show eA
            hss -> return $ concat hss

isNumeric :: HostName -> Bool
isNumeric h = case readMaybe h :: Maybe IPv4 of
    Just _ -> True
    Nothing -> case readMaybe h :: Maybe IPv6 of
        Just _ -> True
        Nothing -> False
