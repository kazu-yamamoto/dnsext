module DNS.Iterative.Query.Norec (norec', norec) where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (
    FlagOp (..),
    defaultResolveActions,
    ractionGenId,
    ractionGetTime,
    ractionLog,
    ractionTimeoutTime,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    ResolveEnv (..),
    ResolveInfo (..),
    defaultResolveInfo,
    udpTcpResolver,
 )
import qualified DNS.Do53.Internal as DNS
import DNS.Types
import qualified Data.List.NonEmpty as NE

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Types

{- Get the answer DNSMessage from the authoritative server.
   Note about flags in request to an authoritative server.
  * RD (Recursion Desired) must be 0 for request to authoritative server
  * EDNS must be enable for DNSSEC OK request -}
norec' :: Bool -> [Address] -> Domain -> TYPE -> ContextT IO (Either DNSError DNSMessage)
norec' dnssecOK aservers name typ = contextT $ \cxt _qctl -> do
    let ris =
            [ defaultResolveInfo
                { rinfoIP = aserver
                , rinfoPort = port
                , rinfoActions =
                    defaultResolveActions
                        { ractionGenId = idGen_ cxt
                        , ractionGetTime = currentSeconds_ cxt
                        , ractionLog = logLines_ cxt
                        , ractionTimeoutTime = 10000000
                        }
                , rinfoUDPRetry = 3
                , rinfoVCLimit = 8 * 1024
                }
            | (aserver, port) <- aservers
            ]
        renv =
            ResolveEnv
                { renvResolver = udpTcpResolver
                , renvConcurrent = True -- should set True if multiple RIs are provided
                , renvResolveInfos = NE.fromList ris
                }
        q = Question name typ IN
        doFlagSet
            | dnssecOK = FlagSet
            | otherwise = FlagClear
        qctl = DNS.rdFlag FlagClear <> DNS.doFlag doFlagSet
    either
        Left
        (Right . DNS.replyDNSMessage)
        <$> DNS.resolve renv q qctl

contextT :: Monad m => (Env -> QueryContext -> m a) -> ContextT m a
contextT k = ReaderT $ ReaderT . k

norec :: Bool -> [Address] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnsssecOK aservers name typ = dnsQueryT $ \cxt _qctl -> do
    let ris =
            [ defaultResolveInfo
                { rinfoIP = aserver
                , rinfoPort = port
                , rinfoActions =
                    defaultResolveActions
                        { ractionGenId = idGen_ cxt
                        , ractionGetTime = currentSeconds_ cxt
                        , ractionLog = logLines_ cxt
                        , ractionTimeoutTime = 10000000
                        }
                , rinfoUDPRetry = 3
                , rinfoVCLimit = 8 * 1024
                }
            | (aserver, port) <- aservers
            ]
        renv =
            ResolveEnv
                { renvResolver = udpTcpResolver
                , renvConcurrent = True -- should set True if multiple RIs are provided
                , renvResolveInfos = NE.fromList ris
                }
        q = Question name typ IN
        doFlagSet
            | dnsssecOK = FlagSet
            | otherwise = FlagClear
        qctl = DNS.rdFlag FlagClear <> DNS.doFlag doFlagSet
    either
        (Left . DnsError)
        (handleResponseError Left Right . DNS.replyDNSMessage)
        <$> DNS.resolve renv q qctl

dnsQueryT :: (Env -> QueryContext -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT k = ExceptT $ ReaderT $ ReaderT . k
