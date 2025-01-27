module DNS.Iterative.Query.Norec (norec') where

-- GHC packages

-- other packages

-- dnsext packages
import DNS.Do53.Client (
    FlagOp (..),
    ResolveActions (..),
    defaultResolveActions,
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
norec' dnssecOK aservers name typ = contextT $ \cxt _qctl _st -> do
    let riActions =
            defaultResolveActions
                { ractionGenId = idGen_ cxt
                , ractionGetTime = currentSeconds_ cxt
                , ractionLog = logLines_ cxt
                , ractionShortLog = shortLog_ cxt
                , ractionTimeoutTime = 5000000
                }
        ris =
            [ defaultResolveInfo
                { rinfoIP = aserver
                , rinfoPort = port
                , rinfoActions = riActions
                , rinfoUDPRetry = 1
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
    fmap DNS.replyDNSMessage <$> DNS.resolve renv q qctl

contextT :: Monad m => (Env -> QueryParam -> QueryState -> m a) -> ContextT m a
contextT k = ReaderT $ ReaderT . (ReaderT .) . k
