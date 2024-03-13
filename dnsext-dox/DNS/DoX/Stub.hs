{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module DNS.DoX.Stub (
    doxPort,
    makeResolver,
    makeOneshotResolver,
    lookupRawDoX,
)
where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Imports
import DNS.DoX.Internal
import qualified DNS.Log as Log
import DNS.SVCB
import DNS.Types
import qualified Data.List.NonEmpty as NE
import Network.Socket (PortNumber)

-- $setup
-- >>> :set -XOverloadedStrings

{- FOURMOLU_DISABLE -}
-- | From APLN to its port number.
--
-- >>> doxPort "dot"
-- 853
doxPort :: ALPN -> PortNumber
doxPort "dot"   = 853
doxPort "doq"   = 853
doxPort "h2"    = 443
doxPort "h2c"   =  80
doxPort "h3"    = 443
doxPort _       =  53

-- | Making resolver according to ALPN.
--
--  The third argument is a path for HTTP query.
makeResolver :: ALPN -> Maybe ShortByteString -> Maybe PipelineResolver
makeResolver alpn mpath = case alpn of
    "tcp" -> Just withTcpResolver
    "dot" -> Just withTlsResolver
    "doq" -> Just withQuicResolver
    "h2"  -> Just $ withHttp2Resolver  (fromMaybe "/dns-query" mpath)
    "h2c" -> Just $ withHttp2cResolver (fromMaybe "/dns-query" mpath)
    "h3"  -> Just $ withHttp3Resolver  (fromMaybe "/dns-query" mpath)
    _     -> Nothing

makeOneshotResolver :: ALPN -> Maybe ShortByteString -> Maybe OneshotResolver
makeOneshotResolver alpn mpath = case alpn of
    "tcp" -> Just tcpResolver
    "dot" -> Just tlsResolver
    "doq" -> Just quicResolver
    "h2"  -> Just $ http2Resolver  (fromMaybe "/dns-query" mpath)
    "h2c" -> Just $ http2cResolver (fromMaybe "/dns-query" mpath)
    "h3"  -> Just $ http3Resolver  (fromMaybe "/dns-query" mpath)
    _     -> Nothing
{- FOURMOLU_ENABLE -}

-- | Looking up SVCB RR first and lookup the target automatically
--   according to the priority of the values of SVCB RR.
lookupRawDoX :: LookupEnv -> Question -> IO (Either DNSError Result)
lookupRawDoX lenv@LookupEnv{..} q = do
    er <- lookup_DNS lenv
    case er of
        Left err -> return $ Left err
        Right Result{..} -> do
            let ss = extraceSVCB resultReply
            logIt lenv ss
            let ri = NE.head $ renvResolveInfos $ lenvResolveEnv
            auto ri ss q lenvQueryControls

lookup_DNS :: LookupEnv -> IO (Either DNSError Result)
lookup_DNS lenv = lookupRaw lenv $ Question "_dns.resolver.arpa" SVCB IN

extraceSVCB :: Reply -> [RD_SVCB]
extraceSVCB Reply{..} = sort (extractResourceData Answer replyDNSMessage) :: [RD_SVCB]

logIt :: LookupEnv -> [RD_SVCB] -> IO ()
logIt LookupEnv{..} ss = ractionLog lenvActions Log.DEMO Nothing r
  where
    multi = RAFlagMultiLine `elem` ractionFlags lenvActions
    r
        | multi = prettyShowRData . toRData <$> ss
        | otherwise = show <$> ss

auto :: ResolveInfo -> [RD_SVCB] -> Resolver
auto ri ss q qctl = resolve (head $ head renvs) q qctl
  where
    renvs = mapMaybe toResolveInfo <$> svcbResolvers ri ss
    toResolveInfo (_, []) = Nothing
    toResolveInfo (alpn, ris) = case makeOneshotResolver alpn Nothing of -- fixme mpath
        Nothing -> Nothing
        Just resolver -> Just $ ResolveEnv resolver True $ NE.fromList ris

svcbResolvers :: ResolveInfo -> [RD_SVCB] -> [[(ALPN, [ResolveInfo])]]
svcbResolvers ri ss = onPriority ri <$> ss

onPriority :: ResolveInfo -> RD_SVCB -> [(ALPN, [ResolveInfo])]
onPriority ri s = case extractSvcParam SPK_ALPN $ svcb_params s of
    Nothing -> []
    Just alpns -> onALPN ri s <$> alpn_names alpns

onALPN :: ResolveInfo -> RD_SVCB -> ALPN -> (ALPN, [ResolveInfo])
onALPN ri s alpn = (alpn, extractResolveInfo ri s alpn)

extractResolveInfo :: ResolveInfo -> RD_SVCB -> ShortByteString -> [ResolveInfo]
extractResolveInfo ri s alpn = updateIPPort <$> ips
  where
    port = maybe (doxPort alpn) port_number $ extractSvcParam SPK_Port $ svcb_params s
    v4s = case extractSvcParam SPK_IPv4Hint $ svcb_params s of
        Nothing -> []
        Just v4 -> show <$> hint_ipv4s v4
    v6s = case extractSvcParam SPK_IPv6Hint $ svcb_params s of
        Nothing -> []
        Just v6 -> show <$> hint_ipv6s v6
    ips = case v4s ++ v6s of
        [] -> []
        xs -> (\h -> (fromString h, port)) <$> xs
    updateIPPort (x, y) = ri{rinfoIP = x, rinfoPort = y}
