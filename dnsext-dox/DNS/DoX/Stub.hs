{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module DNS.DoX.Stub (
    doxPort,
    makeResolver,
    lookupDoX,
)
where

import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Imports
import DNS.DoX.Internal
import qualified DNS.Log as Log
import DNS.SVCB
import DNS.Types
import Network.Socket (HostName, PortNumber)

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
makeResolver :: ALPN -> Maybe ShortByteString -> Maybe OneshotResolver
makeResolver alpn mpath = case alpn of
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
lookupDoX :: LookupConf -> HostName -> TYPE -> IO (Either DNSError Result)
lookupDoX conf domain typ = do
    let resolver = udpTcpResolver
        q = Question "_dns.resolver.arpa" SVCB IN
    withLookupConfAndResolver conf resolver $ \lenv -> do
        er <- lookupRaw lenv q
        case er of
            Left err -> return $ Left err
            Right Result{..} -> do
                let Reply{..} = resultReply
                    ss = sort (extractResourceData Answer replyDNSMessage) :: [RD_SVCB]
                    multi = RAFlagMultiLine `elem` ractionFlags (lconfActions conf)
                    r =
                        if multi
                            then map (prettyShowRData . toRData) ss
                            else map show ss
                ractionLog (lconfActions conf) Log.DEMO Nothing r
                auto domain typ (lconfVCLimit conf) (lenvActions lenv) resultIP ss

auto
    :: HostName
    -> TYPE
    -> VCLimit
    -> ResolveActions
    -> IP
    -> [RD_SVCB]
    -> IO (Either DNSError Result)
auto _ _ _ _ _ [] = return $ Left UnknownDNSError
auto domain typ lim actions ip0 ss0 = loop ss0
  where
    loop [] = return $ Left UnknownDNSError
    loop (s : ss) = do
        let malpns = extractSvcParam SPK_ALPN $ svcb_params s
        case malpns of
            Nothing -> loop ss
            Just alpns -> go $ alpn_names alpns
      where
        go [] = loop ss
        go (alpn : alpns) = case makeResolver alpn Nothing of
            Nothing -> go alpns
            Just resolver -> do
                erply <- resolveDoX s alpn resolver
                case erply of
                    Left _ -> go alpns
                    r -> return r
    q = Question (fromRepresentation domain) typ IN
    resolveDoX s alpn resolver = resolve renv q mempty
      where
        port = maybe (doxPort alpn) port_number $ extractSvcParam SPK_Port $ svcb_params s
        v4s = case extractSvcParam SPK_IPv4Hint $ svcb_params s of
            Nothing -> []
            Just v4 -> show <$> hint_ipv4s v4
        v6s = case extractSvcParam SPK_IPv6Hint $ svcb_params s of
            Nothing -> []
            Just v6 -> show <$> hint_ipv6s v6
        ips = case v4s ++ v6s of
            [] -> [(ip0, port)]
            xs -> map (\h -> (fromString h, port)) xs
        rinfos =
            map
                ( \(x, y) ->
                    defaultResolveInfo
                        { rinfoIP = x
                        , rinfoPort = y
                        , rinfoActions = actions
                        , rinfoVCLimit = lim
                        }
                )
                ips
        renv = ResolveEnv resolver True rinfos
