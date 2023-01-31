{-# LANGUAGE OverloadedStrings #-}

module Operation where

-- import Text.Read (readMaybe)
-- import Data.IP (IP (..))
import DNS.Types (TYPE, DNSError)
import DNS.Do53.Client (QueryControls, LookupConf (..))
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (withLookupConfAndResolver, udpTcpResolver)
import qualified DNS.Do53.Internal as DNS
import DNS.DoX.Internal
import qualified DNS.Types as DNS
import Network.Socket (PortNumber, HostName)
-- import System.Random (randomRIO)

data DoX = Do53 | Auto | DoT | DoQ | DoH2 | DoH3 deriving (Eq, Show)

operate :: Maybe [(HostName,PortNumber)] -> DoX -> HostName -> TYPE -> QueryControls -> IO (Either DNSError DNS.Result)
operate mhps dox domain typ controls = do
  conf <- getCustomConf mhps controls
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

getCustomConf :: Maybe [(HostName,PortNumber)] -> QueryControls -> IO LookupConf
getCustomConf mhps controls = case mhps of
  Nothing  -> return conf
  Just hps -> resolveServer hps conf
  where
    conf = DNS.defaultLookupConf {
        lconfRetry         = 2
      , lconfQueryControls = controls
      , lconfConcurrent    = True
      }

    resolveServer hps c = do
        return $ c { lconfSeeds = DNS.SeedsHostPorts hps }

{-
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
-}
