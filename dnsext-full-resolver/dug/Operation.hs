{-# LANGUAGE OverloadedStrings #-}

module Operation where

import Text.Read (readMaybe)

import Data.IP (IP (..))
import DNS.Types (TYPE, DNSError, DNSMessage)
import DNS.Do53.Client (QueryControls,
               LookupConf (lconfSeeds, lconfRetry, lconfQueryControls))
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (withLookupConfAndResolver, udpTcpResolver)
import DNS.DoX.Internal
import qualified DNS.Types as DNS
import Network.Socket (PortNumber, HostName)
import System.Random (randomRIO)

data DoX = Do53 | Auto | DoT | DoQ | DoH2 | DoH3 deriving (Eq, Show)

operate :: Maybe HostName -> PortNumber -> DoX -> HostName -> TYPE -> QueryControls -> IO (Either DNSError DNSMessage)
operate server port dox domain typ controls = do
  conf <- getCustomConf server port controls
  let lim = 32 * 1024
  let resolver = case dox of
        DoT  -> tlsResolver lim
        DoQ  -> quicResolver lim
        DoH2 -> http2Resolver "/dns-query" lim
        DoH3 -> http3Resolver "/dns-query" lim
        _    -> udpTcpResolver 3 lim
  withLookupConfAndResolver conf resolver $ \env -> do
    let q = DNS.Question (DNS.fromRepresentation domain) typ DNS.classIN
    DNS.lookupRaw env q

getCustomConf :: Maybe HostName -> PortNumber -> QueryControls -> IO LookupConf
getCustomConf mayServer port controls = case mayServer of
  Nothing     -> return conf
  Just server -> resolveServer server conf
  where
    conf = DNS.defaultLookupConf {
        lconfRetry = 2
      , lconfQueryControls = controls
      }

    resolveServer server c = do
        ip <- case readMaybe server of
          Nothing -> queryName server
          Just x  -> return x
        -- print ip
        return $ c { lconfSeeds = DNS.SeedsHostPort (show ip) port }

    queryName :: String -> IO IP
    queryName sname = do
      as <- DNS.withLookupConf DNS.defaultLookupConf $ \env -> do
        let dom = DNS.fromRepresentation sname
        eA  <- DNS.lookupA    env dom
        eQA <- DNS.lookupAAAA env dom
        let catAs = do
              as  <- eA
              qas <- eQA
              return $ map (IPv4 . DNS.a_ipv4) as ++ map (IPv6 . DNS.aaaa_ipv6) qas
        either (fail . show) return catAs
      ix <- randomRIO (0, length as - 1)
      return $ as !! ix
