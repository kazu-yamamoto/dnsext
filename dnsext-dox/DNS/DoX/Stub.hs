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
    er <- lookupRaw lenv $ Question "_dns.resolver.arpa" SVCB IN
    case er of
        Left err -> return $ Left err
        Right Result{..} -> do
            let Reply{..} = resultReply
                ss = sort (extractResourceData Answer replyDNSMessage) :: [RD_SVCB]
                multi = RAFlagMultiLine `elem` ractionFlags lenvActions
                r =
                    if multi
                        then map (prettyShowRData . toRData) ss
                        else map show ss
            ractionLog lenvActions Log.DEMO Nothing r
            auto ss lenv q

auto :: [RD_SVCB] -> LookupEnv -> Question -> IO (Either DNSError Result)
auto ss LookupEnv{..} q = resolve (head renvs) q lenvQueryControls
  where
    ri : _ = renvResolveInfos $ lenvResolveEnv
    renvs : _renvss = svcbResolvers ri ss

svcbResolvers :: ResolveInfo -> [RD_SVCB] -> [[ResolveEnv]]
svcbResolvers ri ss = map (onPriority ri) ss

onPriority :: ResolveInfo -> RD_SVCB -> [ResolveEnv]
onPriority ri s = case extractSvcParam SPK_ALPN (svcb_params s) of
    Nothing -> []
    Just alpns -> catMaybes $ map (onALPN ri s) $ alpn_names alpns

onALPN :: ResolveInfo -> RD_SVCB -> ShortByteString -> Maybe ResolveEnv
onALPN ri s alpn = onALPN' ri s alpn $ makeOneshotResolver alpn Nothing

onALPN' :: ResolveInfo -> RD_SVCB -> ShortByteString -> Maybe OneshotResolver -> Maybe ResolveEnv
onALPN' _ _ _ Nothing = Nothing
onALPN' ri s alpn (Just resolver) = Just $ ResolveEnv resolver True rinfos
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
        xs -> map (\h -> (fromString h, port)) xs
    rinfos = map (\(x, y) -> ri{rinfoIP = x, rinfoPort = y}) ips
