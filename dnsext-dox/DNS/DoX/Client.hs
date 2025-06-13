{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.DoX.Client (
    -- * SVCB information
    lookupSVCBInfo,
    SVCBInfo (..),

    -- * Pipeline resolver
    toPipelineResolvers,
    makePersistentResolver,

    -- * Oneshot resolver
    toResolveEnvs,
    lookupRawDoX,
    makeOneshotResolver,

    -- * ALPN
    doxPort,
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
-- >>> :seti -XOverloadedStrings

----------------------------------------------------------------

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

----------------------------------------------------------------

-- | Making resolver according to ALPN.
--
--  The third argument is a path for HTTP query.
makePersistentResolver :: ALPN -> Maybe PersistentResolver
makePersistentResolver "tcp" = Just tcpPersistentResolver
makePersistentResolver "dot" = Just tlsPersistentResolver
makePersistentResolver "doq" = Just quicPersistentResolver
makePersistentResolver "h2"  = Just http2PersistentResolver
makePersistentResolver "h2c" = Just http2cPersistentResolver
makePersistentResolver "h3"  = Just http3PersistentResolver
makePersistentResolver _     = Nothing

makeOneshotResolver :: ALPN -> Maybe OneshotResolver
makeOneshotResolver "tcp" = Just tcpResolver
makeOneshotResolver "dot" = Just tlsResolver
makeOneshotResolver "doq" = Just quicResolver
makeOneshotResolver "h2"  = Just http2Resolver
makeOneshotResolver "h2c" = Just http2cResolver
makeOneshotResolver "h3"  = Just http3Resolver
makeOneshotResolver _     = Nothing
{- FOURMOLU_ENABLE -}

----------------------------------------------------------------

-- | Looking up SVCB RR first and lookup the target automatically
--   according to the priority of the values of SVCB RR.
lookupRawDoX :: LookupEnv -> Question -> IO (Either DNSError Reply)
lookupRawDoX lenv@LookupEnv{..} q = do
    er <- lookupSVCBInfo lenv
    case er of
        Left err -> return $ Left err
        Right addss -> case toResolveEnvs <$> addss of
            [] -> return $ Left FormatError
            adds : _ -> case adds of
                [] -> return $ Left FormatError
                add : _ -> resolve add q lenvQueryControls

----------------------------------------------------------------

data SVCBInfo = SVCBInfo
    { svcbInfoALPN :: ALPN
    , svcbInfoNameTag :: NameTag
    , svcbInfoResolveInfos :: [ResolveInfo]
    }
    deriving (Show)

lookupSVCBInfo :: LookupEnv -> IO (Either DNSError [[SVCBInfo]])
lookupSVCBInfo lenv@LookupEnv{..} = do
    er <- lookupRaw lenv $ Question "_dns.resolver.arpa" SVCB IN
    case er of
        Left err -> return $ Left err
        Right res -> do
            let ss = extractSVCB res
                -- mainly to pass 'rinfoActions'
                ri = NE.head $ renvResolveInfos lenvResolveEnv
                addss = svcbResolveInfos (replyTag res) ri ss
            logIt lenv ss
            return $ Right addss

extractSVCB :: Reply -> [RD_SVCB]
extractSVCB Reply{..} = sort (extractResourceData Answer replyDNSMessage) :: [RD_SVCB]

logIt :: LookupEnv -> [RD_SVCB] -> IO ()
logIt LookupEnv{..} ss = ractionLog lenvActions Log.DEMO Nothing r
  where
    r = prettyShowRData . toRData <$> ss

----------------------------------------------------------------

toResolveEnvs :: [SVCBInfo] -> [ResolveEnv]
toResolveEnvs sis = mapMaybe toResolveEnv sis

toResolveEnv :: SVCBInfo -> Maybe ResolveEnv
toResolveEnv SVCBInfo{..}
    | null svcbInfoResolveInfos = Nothing
    | otherwise = case makeOneshotResolver svcbInfoALPN of
        Nothing -> Nothing
        Just resolver -> Just $ ResolveEnv resolver True $ NE.fromList svcbInfoResolveInfos

toPipelineResolvers :: [SVCBInfo] -> [[PipelineResolver]]
toPipelineResolvers sis = toPipelineResolver <$> sis

toPipelineResolver :: SVCBInfo -> [PipelineResolver]
toPipelineResolver SVCBInfo{..}
    | null svcbInfoResolveInfos = []
    | otherwise = case makePersistentResolver svcbInfoALPN of
        Nothing -> []
        Just resolver -> resolver <$> svcbInfoResolveInfos

----------------------------------------------------------------

svcbResolveInfos :: NameTag -> ResolveInfo -> [RD_SVCB] -> [[SVCBInfo]]
svcbResolveInfos ntag ri ss = onPriority ntag ri <$> ss

onPriority :: NameTag -> ResolveInfo -> RD_SVCB -> [SVCBInfo]
onPriority ntag ri s = case extractSvcParam SPK_ALPN $ svcb_params s of
    Nothing -> []
    Just alpns -> onALPN ntag ri s <$> alpn_names alpns

onALPN :: NameTag -> ResolveInfo -> RD_SVCB -> ALPN -> SVCBInfo
onALPN ntag ri s alpn =
    SVCBInfo
        { svcbInfoALPN = alpn
        , svcbInfoNameTag = ntag
        , svcbInfoResolveInfos = extractResolveInfo ntag ri s alpn
        }

extractResolveInfo :: NameTag -> ResolveInfo -> RD_SVCB -> ShortByteString -> [ResolveInfo]
extractResolveInfo ntag ri s alpn = updateIPPort <$> ips
  where
    params = svcb_params s
    target = svcb_target s
    port = maybe (doxPort alpn) port_number $ extractSvcParam SPK_Port params
    mdohpath = dohpath <$> extractSvcParam SPK_DoHPath params
    v4s = case extractSvcParam SPK_IPv4Hint params of
        Nothing -> []
        Just v4 -> show <$> hint_ipv4s v4
    v6s = case extractSvcParam SPK_IPv6Hint params of
        Nothing -> []
        Just v6 -> show <$> hint_ipv6s v6
    ips = case v4s ++ v6s of
        [] -> [(nameTagIP ntag, port)] -- no "ipv4hint" nor "ipv6hint"
        xs -> (\h -> (fromString h, port)) <$> xs
    updateIPPort (x, y) =
        ri
            { rinfoIP = x
            , rinfoPort = y
            , rinfoPath = mdohpath
            , rinfoServerName = Just $ init $ toRepresentation target
            }
