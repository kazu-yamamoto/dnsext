{-# LANGUAGE RecordWildCards #-}

module DNS.Do53.Lookup (
  -- * Lookups returning requested RData
    lookup
  , lookupAuth
  , lookup'
  , lookupAuth'
  -- * Lookups returning DNS Messages
  , lookupRaw
  , lookupRawCtl
  -- * DNS Message procesing
  , fromDNSMessage
  ) where

import Control.Exception as E
import DNS.Types hiding (Seconds)
import Prelude hiding (lookup)

import DNS.Do53.Imports
import DNS.Do53.Memo
import DNS.Do53.Query
import DNS.Do53.Resolve
import DNS.Do53.Types

-- $setup
-- >>> import DNS.Do53.Do53

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
--   >>> withResolvConf defaultResolvConf $ \seeds -> lookup seeds "www.example.com" A
--   Right [93.184.216.34]
--
lookup :: Seeds -> Domain -> TYPE -> IO (Either DNSError [RData])
lookup = lookupSection Answer

-- | Look up resource records of a specified type for a domain,
--   collecting the results
--   from the AUTHORITY section of the response.
--   See the documentation of 'lookupRaw'
--   to understand the concrete behavior.
--   Cache is used even if 'resolvCache' is 'Just'.
lookupAuth :: Seeds -> Domain -> TYPE -> IO (Either DNSError [RData])
lookupAuth = lookupSection Authority

lookup' :: ResourceData a => TYPE -> Seeds -> Domain -> IO (Either DNSError [a])
lookup' typ rlv dom = unwrap <$> lookup rlv dom typ

lookupAuth' :: ResourceData a => TYPE -> Seeds -> Domain -> IO (Either DNSError [a])
lookupAuth' typ rlv dom = unwrap <$> lookupAuth rlv dom typ

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
              -> Seeds
              -> Domain
              -> TYPE
              -> IO (Either DNSError [RData])
lookupSection section rlv dom typ
  | section == Authority = lookupFreshSection rlv dom typ section
  | otherwise = case mcacheConf of
      Nothing           -> lookupFreshSection rlv dom typ section
      Just cacheconf    -> lookupCacheSection rlv dom typ cacheconf
  where
    mcacheConf = resolvCache $ resolvConf rlv

lookupFreshSection :: Seeds
                   -> Domain
                   -> TYPE
                   -> Section
                   -> IO (Either DNSError [RData])
lookupFreshSection rlv dom typ section = do
    eans <- lookupRaw rlv dom typ
    case eans of
      Left err  -> return $ Left err
      Right ans -> return $ fromDNSMessage ans toRD
  where
    correct ResourceRecord{..} = rrtype == typ
    toRD = map rdata . filter correct . sectionF
    sectionF = case section of
      Answer    -> answer
      Authority -> authority

lookupCacheSection :: Seeds
                   -> Domain
                   -> TYPE
                   -> CacheConf
                   -> IO (Either DNSError [RData])
lookupCacheSection rlv dom typ cconf = do
    mx <- lookupCache (dom,typ) c
    case mx of
      Nothing -> do
          eans <- lookupRaw rlv dom typ
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
                      cacheNegative cconf c key v ans
                      return v
                  Left e -> return $ Left e
                  Right [] -> do
                      let v = Right []
                      cacheNegative cconf c key v ans
                      return v
                  Right rss -> do
                      cachePositive cconf c key rss
                      return $ Right $ map rdata rss
      Just (_,x) -> return x
  where
    toRR = filter (typ `isTypeOf`) . answer
    c = fromJust $ cache rlv
    key = (dom,typ)

cachePositive :: CacheConf -> Cache -> Key -> [ResourceRecord] -> IO ()
cachePositive cconf c key rss
  | ttl == 0  = return () -- does not cache anything
  | otherwise = insertPositive cconf c key (Right rds) ttl
  where
    rds = map rdata rss
    ttl = minimum $ map rrttl rss -- rss is non-empty

insertPositive :: CacheConf -> Cache -> Key -> Entry -> TTL -> IO ()
insertPositive CacheConf{..} c k v ttl = when (ttl /= 0) $ do
    ctime <- getEpochTime
    let tim = ctime + life
    insertCache k tim v c
  where
    life :: EpochTime
    life = fromIntegral (minimumTTL `max` (maximumTTL `min` ttl))

cacheNegative :: CacheConf -> Cache -> Key -> Entry -> DNSMessage -> IO ()
cacheNegative cconf c key v ans = case soas of
  []    -> return () -- does not cache anything
  soa:_ -> insertNegative cconf c key v $ rrttl soa
  where
    soas = filter (SOA `isTypeOf`) $ authority ans

insertNegative :: CacheConf -> Cache -> Key -> Entry -> TTL -> IO ()
insertNegative _ c k v ttl = when (ttl /= 0) $ do
    ctime <- getEpochTime
    let tim = ctime + life
    insertCache k tim v c
  where
    life :: EpochTime
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
-- If multiple DNS servers are specified 'ResolvConf' ('RCHostNames ')
-- or found ('RCFilePath'), either sequential lookup or
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
--   withResolvConf defaultResolvConf $ \\seeds -> lookupRaw seeds \"www.example.com\" A
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
--   >>> withResolvConf defaultResolvConf $ \seeds -> lookupRaw seeds "mew.org" AXFR
--   Left InvalidAXFRLookup
--
lookupRaw :: Seeds      -- ^ Seeds obtained via 'withResolvConf'
          -> Domain     -- ^ Query domain
          -> TYPE       -- ^ Query RRtype
          -> IO (Either DNSError DNSMessage)
lookupRaw rslv dom typ = lookupRawCtl rslv dom typ mempty

-- | Similar to 'lookupRaw', but the default values of the RD, AD, CD and DO
-- flag bits, as well as various EDNS features, can be adjusted via the
-- 'QueryControls' parameter.
--
lookupRawCtl :: Seeds         -- ^ Seeds obtained via 'withResolvConf'
             -> Domain        -- ^ Query domain
             -> TYPE          -- ^ Query RRtype
             -> QueryControls -- ^ Query flag and EDNS overrides
             -> IO (Either DNSError DNSMessage)
lookupRawCtl rslv dom typ ctls = E.try $ resolve rslv dom typ ctls
