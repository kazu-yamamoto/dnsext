{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module DNS.Do53.Lookup (
  -- * Lookups returning requested RData
    lookup
  , lookupAuth
  , lookup'
  , lookupAuth'
  -- * Lookups returning DNS Messages
  , lookupRaw
  -- * DNS Message procesing
  , fromDNSMessage
  -- * Misc
  , withLookupConf
  , withLookupConfAndResolver
  , modifyLookupEnv
  ) where

import Control.Exception as E
import DNS.Types hiding (Seconds)
import Prelude hiding (lookup)
import Network.Socket (HostName, PortNumber, HostName, PortNumber)

import DNS.Do53.Do53
import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Resolve
import DNS.Do53.System
import DNS.Do53.Types

data Section = Answer | Authority deriving (Eq, Ord, Show)

----------------------------------------------------------------

-- | Look up resource records of a specified type for a domain,
--   collecting the results
--   from the ANSWER section of the response.
--   See the documentation of 'lookupRaw'
--   to understand the concrete behavior.
--   Cache is used if 'resolvCache' is 'Just'.
--
--   Example:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookup env "www.example.com" A
--   Right [93.184.216.34]
--
lookup :: LookupEnv -> Domain -> TYPE -> IO (Either DNSError [RData])
lookup env dom typ = lookupSection Answer env q
  where
    q = Question dom typ classIN

-- | Look up resource records of a specified type for a domain,
--   collecting the results
--   from the AUTHORITY section of the response.
--   See the documentation of 'lookupRaw'
--   to understand the concrete behavior.
--   Cache is used even if 'resolvCache' is 'Just'.
lookupAuth :: LookupEnv -> Domain -> TYPE -> IO (Either DNSError [RData])
lookupAuth env dom typ = lookupSection Authority env q
  where
    q = Question dom typ classIN

lookup' :: ResourceData a => TYPE -> LookupEnv -> Domain -> IO (Either DNSError [a])
lookup' typ env dom = unwrap <$> lookup env dom typ

lookupAuth' :: ResourceData a => TYPE -> LookupEnv -> Domain -> IO (Either DNSError [a])
lookupAuth' typ env dom = unwrap <$> lookupAuth env dom typ

unwrap :: ResourceData a => Either DNSError [RData] -> Either DNSError [a]
unwrap erds = case erds of
    Left err  -> Left err
    Right rds -> mapM unTag rds

unTag :: ResourceData a => RData -> Either DNSError a
unTag rd = case fromRData rd of
  Nothing -> Left UnexpectedRDATA
  Just x  -> Right x

----------------------------------------------------------------

-- | Looking up resource records of a domain. The first parameter is one of
--   the field accessors of the 'DNSMessage' type -- this allows you to
--   choose which section (answer, authority, or additional) you would like
--   to inspect for the result.

lookupSection :: Section
              -> LookupEnv
              -> Question
              -> IO (Either DNSError [RData])
lookupSection section env q
  | section == Authority = lookupFreshSection env q section
  | otherwise = case lenvCache env of
      Nothing -> lookupFreshSection env q section
      Just _  -> lookupCacheSection env q

lookupFreshSection :: LookupEnv
                   -> Question
                   -> Section
                   -> IO (Either DNSError [RData])
lookupFreshSection env q@Question{..} section = do
    eans <- lookupRaw env q
    case eans of
      Left err  -> return $ Left err
      Right ans -> return $ fromDNSMessage ans toRD
  where
    correct ResourceRecord{..} = rrtype == qtype
    toRD = map rdata . filter correct . sectionF
    sectionF = case section of
      Answer    -> answer
      Authority -> authority

lookupCacheSection :: LookupEnv
                   -> Question
                   -> IO (Either DNSError [RData])
lookupCacheSection env@LookupEnv{..} q@Question{..} = do
    mx <- lookupCache q c
    case mx of
      Nothing -> do
          eans <- lookupRaw env q
          now <- ractionGetTime lenvActions
          case eans of
            Left  err ->
                -- Probably a network error happens.
                -- We do not cache anything.
                return $ Left err
            Right ans -> do
                let ex = fromDNSMessage ans toRR
                case ex of
                  Left NameError -> do
                      let v = Left NameError
                      cacheNegative cconf c q now v ans
                      return v
                  Left e -> return $ Left e
                  Right [] -> do
                      let v = Right []
                      cacheNegative cconf c q now v ans
                      return v
                  Right rss -> do
                      cachePositive cconf c q now rss
                      return $ Right $ map rdata rss
      Just (_,x) -> return x
  where
    toRR = filter (qtype `isTypeOf`) . answer
    (c, cconf) = fromJust lenvCache

cachePositive :: CacheConf -> Cache -> Key -> EpochTime -> [ResourceRecord] -> IO ()
cachePositive cconf c k now rss
  | ttl == 0  = return () -- does not cache anything
  | otherwise = insertPositive cconf c k now v ttl
  where
    rds = map rdata rss
    v = Right rds
    ttl = minimum $ map rrttl rss -- rss is non-empty

insertPositive :: CacheConf -> Cache -> Key -> EpochTime -> Entry -> TTL -> IO ()
insertPositive CacheConf{..} c k now v ttl = when (ttl /= 0) $ do
    let p = now + life
    insertCache k p v c
  where
    life = fromIntegral (minimumTTL `max` (maximumTTL `min` ttl))

cacheNegative :: CacheConf -> Cache -> Key -> EpochTime -> Entry -> DNSMessage -> IO ()
cacheNegative cconf c k now v ans = case soas of
  []    -> return () -- does not cache anything
  soa:_ -> insertNegative cconf c k now v $ rrttl soa
  where
    soas = filter (SOA `isTypeOf`) $ authority ans

insertNegative :: CacheConf -> Cache -> Key -> EpochTime -> Entry -> TTL -> IO ()
insertNegative _ c k now v ttl = when (ttl /= 0) $ do
    let p = now + life
    insertCache k p v c
  where
    life = fromIntegral ttl

isTypeOf :: TYPE -> ResourceRecord -> Bool
isTypeOf t ResourceRecord{..} = rrtype == t

----------------------------------------------------------------

-- | Look up a name and return the entire DNS Response.
--
-- For a given DNS server, the queries are done:
--
--  * A new UDP socket bound to a new local port is created and
--    a new identifier is created atomically from the cryptographically
--    secure pseudo random number generator for the target DNS server.
--    Then UDP queries are tried with the limitation of 'resolvRetry'
--    (use EDNS if specifiecd).
--    If it appears that the target DNS server does not support EDNS,
--    it falls back to traditional queries.
--
--  * If the response is truncated, a new TCP socket bound to a new
--    local port is created. Then exactly one TCP query is retried.
--
--
-- If multiple DNS servers are specified 'LookupConf' ('SeedsHostNames ')
-- or found ('SeedsFilePath'), either sequential lookup or
-- concurrent lookup is carried out:
--
--  * In sequential lookup ('resolvConcurrent' is False),
--    the query procedure above is processed
--    in the order of the DNS servers sequentially until a successful
--    response is received.
--
--  * In concurrent lookup ('resolvConcurrent' is True),
--    the query procedure above is processed
--    for each DNS server concurrently.
--    The first received response is accepted even if
--    it is an error.
--
--  Cache is not used even if 'resolvCache' is 'Just'.
--
--
--   The example code:
--
--   @
--   withLookupConf defaultLookupConf $ \\env -> lookupRaw env $ Question \"www.example.com\" A classIN
--   @
--
--   And the (formatted) expected output:
--
--   @
--   Right (DNSMessage
--           { header = DNSHeader
--                        { identifier = 1,
--                          flags = DNSFlags
--                                    { qOrR = QR_Response,
--                                      opcode = OP_STD,
--                                      authAnswer = False,
--                                      trunCation = False,
--                                      recDesired = True,
--                                      recAvailable = True,
--                                      rcode = NoErr,
--                                      authenData = False
--                                    },
--                        },
--             question = [Question { qname = \"www.example.com.\",
--                                    qtype = A}],
--             answer = [ResourceRecord {rrname = \"www.example.com.\",
--                                       rrtype = A,
--                                       rrttl = 800,
--                                       rdlen = 4,
--                                       rdata = 93.184.216.119}],
--             authority = [],
--             additional = []})
--  @
--
--  AXFR requests cannot be performed with this interface.
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupRaw env $ Question "mew.org" AXFR classIN
--   Left InvalidAXFRLookup
--
lookupRaw :: LookupEnv      -- ^ LookupEnv obtained via 'withLookupConf'
          -> Question
          -> IO (Either DNSError DNSMessage)
lookupRaw LookupEnv{..} q = E.try $ resolve lenvResolvEnv q lenvQueryControls

----------------------------------------------------------------

-- 53 is the standard port number for domain name servers as assigned by IANA
dnsPort :: PortNumber
dnsPort = 53

findAddrPorts :: Seeds -> IO [(HostName,PortNumber)]
findAddrPorts (SeedsHostName   nh)  = return [(nh, dnsPort)]
findAddrPorts (SeedsHostPort  nh p) = return [(nh, p)]
findAddrPorts (SeedsHostNames nss)  = return $ map (,dnsPort) nss
findAddrPorts (SeedsFilePath  file) = map (,dnsPort) <$> getDefaultDnsServers file

----------------------------------------------------------------

-- | Giving a thread-safe 'LookupEnv' to the function of the second
--   argument.
withLookupConf :: LookupConf -> (LookupEnv -> IO a) -> IO a
withLookupConf lconf@LookupConf{..} f = do
    let resolver = udpTcpResolver lconfRetry lconfLimit
    withLookupConfAndResolver lconf resolver f

withLookupConfAndResolver :: LookupConf -> Resolver -> (LookupEnv -> IO a) -> IO a
withLookupConfAndResolver LookupConf{..} resolver f = do
    mcache <- case lconfCacheConf of
      Just cacheconf -> do
          cache <- newCache (pruningDelay cacheconf)
          return $ Just (cache, cacheconf)
      Nothing -> return Nothing
    ris <- findAddrPorts lconfSeeds
    let renv = resolvEnv resolver lconfConcurrent lconfActions ris
        lenv = LookupEnv mcache lconfQueryControls lconfConcurrent renv lconfActions
    f lenv

resolvEnv :: Resolver -> Bool -> ResolvActions -> [(HostName, PortNumber)] -> ResolvEnv
resolvEnv resolver conc actions hps = ResolvEnv resolver conc ris
  where
    ris = resolvInfos actions hps

resolvInfos :: ResolvActions -> [(HostName, PortNumber)] -> [ResolvInfo]
resolvInfos actions hps = map mk hps
  where
    mk (h,p) = ResolvInfo {
            rinfoHostName   = h
          , rinfoPortNumber = p
          , rinfoActions    = actions
          }

modifyLookupEnv :: Resolver -> [(HostName, PortNumber)] -> LookupEnv -> LookupEnv
modifyLookupEnv resolver hps lenv@LookupEnv{..} = lenv {
    lenvResolvEnv = renv
  }
  where
    renv = resolvEnv resolver lenvConcurrent lenvActions hps
