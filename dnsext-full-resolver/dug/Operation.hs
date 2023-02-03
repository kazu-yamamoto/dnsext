{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Operation where

import DNS.Do53.Client (QueryControls, LookupConf(..), Seeds(..))
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (withLookupConfAndResolver, udpTcpResolver, Result(..), Result(..))
import DNS.DoX.Stub
import DNS.SVCB
import DNS.Types (DNSError, Question(..))
import qualified DNS.Types as DNS
import Data.ByteString.Short (ShortByteString)
import Data.IP (IPv4, IPv6)
import Network.Socket (PortNumber, HostName)
import Text.Read (readMaybe)

operate :: [HostName] -> PortNumber -> ShortByteString -> HostName -> TYPE -> QueryControls -> IO (Either DNSError Result)
operate mserver port dox domain typ controls | dox == "auto" = do
  conf <- getCustomConf mserver port controls
  lookupDoX conf domain typ
operate mserver port dox domain typ controls = do
    conf <- getCustomConf mserver port controls
    let lim = DNS.lconfLimit conf
        resolver = case makeResolver dox lim Nothing of
          Just r -> r
          Nothing -> let retry = DNS.lconfRetry conf
                     in udpTcpResolver lim retry
    withLookupConfAndResolver conf resolver $ \env -> do
        let q = Question (DNS.fromRepresentation domain) typ DNS.classIN
        DNS.lookupRaw env q

getCustomConf :: [HostName] -> PortNumber ->  QueryControls -> IO LookupConf
getCustomConf mserver port controls = case mserver of
  [] -> return conf
  hs -> do
      as <- concat <$> mapM toNumeric hs
      let aps = map (,port) as
      return $ conf { lconfSeeds = SeedsHostPorts aps }
  where
    conf = DNS.defaultLookupConf {
        lconfRetry         = 2
      , lconfQueryControls = controls
      , lconfConcurrent    = True
      }

    toNumeric :: HostName -> IO [HostName]
    toNumeric sname | isNumeric sname = return [sname]
    toNumeric sname = DNS.withLookupConf DNS.defaultLookupConf $ \env -> do
        let dom = DNS.fromRepresentation sname
        eA  <- DNS.lookupA    env dom
        eQA <- DNS.lookupAAAA env dom
        let eas = do
              as  <- eA
              qas <- eQA
              return $ map (show . DNS.a_ipv4) as ++ map (show . DNS.aaaa_ipv6) qas
        either (fail . show) return eas

isNumeric :: HostName -> Bool
isNumeric h = case readMaybe h :: Maybe IPv4 of
  Just _  -> True
  Nothing -> case readMaybe h :: Maybe IPv6 of
    Just _  -> True
    Nothing -> False
