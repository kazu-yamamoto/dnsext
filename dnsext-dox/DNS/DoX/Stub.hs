{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module DNS.DoX.Stub (
    doxPort
  , makeResolver
  , lookupDoX
  ) where

import Control.Exception (try)
import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Internal
import DNS.SVCB
import DNS.Types
import Network.Socket (PortNumber, HostName)

import DNS.DoX.Imports

doxPort :: ShortByteString -> PortNumber
doxPort "dot" = 853
doxPort "doq" = 853
doxPort "h2"  = 443
doxPort "h3"  = 443
doxPort _     = 53

makeResolver :: ShortByteString -> VCLimit -> Maybe ShortByteString -> Maybe Resolver
makeResolver dox lim mpath = case dox of
  "dot" -> Just $ tlsResolver lim
  "doq" -> Just $ quicResolver lim
  "h2"  -> Just $ http2Resolver (fromMaybe "/dns-query" mpath) lim
  "h3"  -> Just $ http3Resolver (fromMaybe "/dns-query" mpath) lim
  _     -> Nothing

lookupDoX :: LookupConf -> HostName -> TYPE -> IO (Either DNSError Result)
lookupDoX conf domain typ = do
  let lim = lconfLimit conf
      retry = lconfRetry conf
      resolver = udpTcpResolver retry lim
      q = Question "_dns.resolver.arpa" SVCB classIN
  withLookupConfAndResolver conf resolver $ \lenv -> do
      er <- lookupRaw lenv q
      case er of
        Left err -> return $ Left err
        Right Result{..} -> do
            let Reply{..} = resultReply
                ss = sort (extractResourceData Answer replyDNSMessage) :: [RD_SVCB]
            auto domain typ lim (lenvActions lenv) resultHostName ss

auto :: HostName -> TYPE -> Int -> ResolvActions -> HostName -> [RD_SVCB] -> IO (Either DNSError Result)
auto _ _ _ _ _ [] = return $ Left UnknownDNSError
auto domain typ lim actions server ss0 = loop ss0
  where
    loop [] = return $ Left UnknownDNSError
    loop (RD_SVCB{..}:ss) = do
        let malpns = extractSvcParam SPK_ALPN svcb_params
        case malpns of
          Nothing -> loop ss
          Just alpns -> go $ alpn_names alpns
       where
         q = Question (fromRepresentation domain) typ classIN
         go [] = loop ss
         go (alpn:alpns) = case makeResolver alpn lim Nothing of
           Nothing -> go alpns
           Just resolver  -> do
               let port = maybe (doxPort alpn) port_number $ extractSvcParam SPK_Port svcb_params
                   v4s = case extractSvcParam SPK_IPv4Hint svcb_params of
                     Nothing -> []
                     Just v4 -> show <$> hint_ipv4s v4
                   v6s = case extractSvcParam SPK_IPv6Hint svcb_params of
                     Nothing -> []
                     Just v6 -> show <$> hint_ipv6s v6
                   ips = case v4s ++ v6s of
                     [] -> [(server,port)]
                     xs -> map (,port) xs
                   rinfos = map (\(x,y) -> ResolvInfo x y actions) ips
                   renv = ResolvEnv resolver True rinfos
               mrply <- try $ resolve renv q mempty
               case mrply of
                 Left _ -> go alpns
                 _      -> return mrply
