{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module Operation where

import DNS.Do53.Client (QueryControls, LookupConf (..))
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (withLookupConfAndResolver, udpTcpResolver)
import qualified DNS.Do53.Internal as DNS
import DNS.DoX.Internal
import DNS.Types (TYPE, DNSError)
import qualified DNS.Types as DNS
import Data.IP (IPv4, IPv6)
import Network.Socket (PortNumber, HostName)
import Text.Read (readMaybe)

data DoX = Do53 | Auto | DoT | DoQ | DoH2 | DoH3 deriving (Eq, Show)

operate :: [HostName] -> PortNumber -> DoX -> HostName -> TYPE -> QueryControls -> IO (Either DNSError DNS.Result)
operate mserver port dox domain typ controls = do
  conf <- getCustomConf mserver port controls
  let lim = DNS.lconfLimit conf
      retry = DNS.lconfRetry conf
  let resolver = case dox of
        DoT  -> tlsResolver lim
        DoQ  -> quicResolver lim
        DoH2 -> http2Resolver "/dns-query" lim
        DoH3 -> http3Resolver "/dns-query" lim
        _    -> udpTcpResolver retry lim
  withLookupConfAndResolver conf resolver $ \env -> do
    let q = DNS.Question (DNS.fromRepresentation domain) typ DNS.classIN
    DNS.lookupRaw env q

getCustomConf :: [HostName] -> PortNumber ->  QueryControls -> IO LookupConf
getCustomConf mserver port controls = case mserver of
  [] -> return conf
  hs -> do
      as <- concat <$> mapM toNumeric hs
      let aps = map (,port) as
      return $ conf { lconfSeeds = DNS.SeedsHostPorts aps }
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
