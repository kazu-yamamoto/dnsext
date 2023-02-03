{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Operation where

import Control.Exception (try)
import DNS.Do53.Client (QueryControls, LookupConf(..), Seeds(..))
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (withLookupConfAndResolver, udpTcpResolver, LookupEnv(..), Result(..), Reply(..), Result(..), ResolvEnv(..), ResolvInfo(..), Resolver, ResolvActions(..))
import qualified DNS.Do53.Internal as DNS
import DNS.DoX.Internal
import DNS.SVCB
import DNS.Types (DNSError, Question(..))
import qualified DNS.Types as DNS
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Short as Short
import Data.IP (IPv4, IPv6)
import Data.List (sort)
import Data.Maybe (fromMaybe)
import Network.Socket (PortNumber, HostName)
import Text.Read (readMaybe)

data DoX = Do53 | Auto | DoT | DoQ | DoH2 | DoH3 deriving (Eq, Show)

doxPort :: DoX -> PortNumber
doxPort Do53 = 53
doxPort Auto = 53
doxPort DoT  = 853
doxPort DoQ  = 853
doxPort DoH2 = 443
doxPort DoH3 = 443

toDoX :: String -> DoX
toDoX "dot" = DoT
toDoX "doq" = DoQ
toDoX "h2"  = DoH2
toDoX "h3"  = DoH3
toDoX _     = Auto

makeResolver :: DoX -> DNS.VCLimit -> Maybe DNS.UDPRetry -> Maybe Short.ShortByteString -> Resolver
makeResolver dox lim mretry mpath = case dox of
  DoT  -> tlsResolver lim
  DoQ  -> quicResolver lim
  DoH2 -> http2Resolver (fromMaybe "/dns-query" mpath) lim
  DoH3 -> http3Resolver (fromMaybe "/dns-query" mpath) lim
  _    -> udpTcpResolver (fromMaybe 3 mretry) lim

operate :: [HostName] -> PortNumber -> DoX -> HostName -> TYPE -> QueryControls -> IO (Either DNSError Result)
operate mserver port Auto domain typ controls = do
  conf <- getCustomConf mserver port controls
  let lim = DNS.lconfLimit conf
      retry = DNS.lconfRetry conf
      resolver = udpTcpResolver retry lim
      q = Question "_dns.resolver.arpa" SVCB DNS.classIN
  withLookupConfAndResolver conf resolver $ \lenv -> do
      er <- DNS.lookupRaw lenv q
      case er of
        Left err -> return $ Left err
        Right Result{..} -> do
            let Reply{..} = resultReply
                ss = sort (DNS.extractResourceData DNS.Answer replyDNSMessage) :: [RD_SVCB]
            auto domain typ lim (lenvActions lenv) resultHostName ss
operate mserver port dox domain typ controls = do
  conf <- getCustomConf mserver port controls
  let lim = DNS.lconfLimit conf
      retry = DNS.lconfRetry conf
      resolver = makeResolver dox lim (Just retry) Nothing
  withLookupConfAndResolver conf resolver $ \env -> do
    let q = Question (DNS.fromRepresentation domain) typ DNS.classIN
    DNS.lookupRaw env q

auto :: HostName -> TYPE -> Int -> ResolvActions -> HostName -> [RD_SVCB] -> IO (Either DNSError Result)
auto _ _ _ _ _ [] = return $ Left DNS.UnknownDNSError
auto domain typ lim actions server ss0 = loop ss0
  where
    loop [] = return $ Left DNS.UnknownDNSError
    loop (RD_SVCB{..}:ss) = do
        let malpns = extractSvcParam SPK_ALPN svcb_params
        case malpns of
          Nothing -> loop ss
          Just alpns -> go $ alpn_names alpns
       where
         q = Question (DNS.fromRepresentation domain) typ DNS.classIN
         go [] = loop ss
         go (alpn:alpns) = case toDoX (BS.unpack (Short.fromShort alpn)) of
           Auto -> go alpns
           dox  -> do
               let port = maybe (doxPort dox) port_number $ extractSvcParam SPK_Port svcb_params
                   v4s = case extractSvcParam SPK_IPv4Hint svcb_params of
                     Nothing -> []
                     Just v4 -> show <$> hint_ipv4s v4
                   v6s = case extractSvcParam SPK_IPv6Hint svcb_params of
                     Nothing -> []
                     Just v6 -> show <$> hint_ipv6s v6
                   ips = case v4s ++ v6s of
                     [] -> [(server,port)]
                     xs -> map (,port) xs
                   resolver = makeResolver dox lim Nothing Nothing
                   rinfos = map (\(x,y) -> ResolvInfo x y actions) ips
                   renv = ResolvEnv resolver True rinfos
               mrply <- try $ DNS.resolve renv q mempty
               case mrply of
                 Left _ -> go alpns
                 _      -> return mrply

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
