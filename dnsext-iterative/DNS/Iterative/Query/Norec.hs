module DNS.Iterative.Query.Norec (norec) where

-- GHC packages
import qualified Control.Exception as E
import System.Timeout (timeout)

-- other packages

-- dnsext packages
import DNS.Do53.Client (
    FlagOp (..),
    QueryControls (..),
    defaultResolvActions,
    ractionGenId,
    ractionGetTime,
    ractionLog,
    ractionTimeout,
 )
import qualified DNS.Do53.Client as DNS
import DNS.Do53.Internal (
    ResolvEnv (..),
    ResolvInfo (..),
    defaultResolvInfo,
    udpTcpResolver,
 )
import qualified DNS.Do53.Internal as DNS
import DNS.Types hiding (InvalidEDNS, flags)
import qualified DNS.Types as DNS
import Data.IP (IP)

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Types

{- Get the answer DNSMessage from the authoritative server.
   Note about flags in request to an authoritative server.
  * RD (Recursion Desired) must be 0 for request to authoritative server
  * EDNS must be enable for DNSSEC OK request -}
norec :: Bool -> [IP] -> Domain -> TYPE -> DNSQuery DNSMessage
norec dnsssecOK aservers name typ = dnsQueryT $ \cxt _qctl -> do
    let ris =
            [ defaultResolvInfo
                { rinfoHostName = show aserver
                , rinfoActions =
                    defaultResolvActions
                        { ractionGenId = idGen_ cxt
                        , ractionGetTime = currentSeconds_ cxt
                        , ractionLog = logLines_ cxt
                        , ractionTimeout = timeout 10000000
                        }
                }
            | aserver <- aservers
            ]
        renv =
            ResolvEnv
                { renvResolver = udpTcpResolver 3 (32 * 1024) -- 3 is retry
                , renvConcurrent = True -- should set True if multiple RIs are provided
                , renvResolvInfos = ris
                }
        q = Question name typ IN
        doFlagSet
            | dnsssecOK = FlagSet
            | otherwise = FlagClear
        qctl = DNS.rdFlag FlagClear <> DNS.doFlag doFlagSet
    either
        (Left . DnsError)
        (handleResponseError Left Right . DNS.replyDNSMessage . DNS.resultReply)
        <$> E.try (DNS.resolve renv q qctl)

-- responseErrEither = handleResponseError Left Right  :: DNSMessage -> Either QueryError DNSMessage
-- responseErrDNSQuery = handleResponseError throwE return  :: DNSMessage -> DNSQuery DNSMessage

handleResponseError :: (QueryError -> p) -> (DNSMessage -> p) -> DNSMessage -> p
handleResponseError e f msg
    | not (DNS.isResponse flags) = e $ NotResponse (DNS.isResponse flags) msg
    | DNS.ednsHeader msg == DNS.InvalidEDNS =
        e $ InvalidEDNS (DNS.ednsHeader msg) msg
    | DNS.rcode flags
        `notElem` [DNS.NoErr, DNS.NameErr] =
        e $ HasError (DNS.rcode flags) msg
    | otherwise = f msg
  where
    flags = DNS.flags $ DNS.header msg

dnsQueryT
    :: (Env -> QueryControls -> IO (Either QueryError a)) -> DNSQuery a
dnsQueryT k = ExceptT $ ReaderT $ ReaderT . k
