{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Simple, high-level DNS lookup functions for clients.
--
--   All of the lookup functions necessary run in IO since they
--   interact with the network. The return types are similar, but
--   differ in what can be returned from a successful lookup.
--
--   We can think of the return type as either \"what I asked for\" or
--   \"an error\". For example, the 'lookupA' function, if successful,
--   will return a list of 'IPv4'. The 'lookupMX' function will
--   instead return a list of @RD_MX@.
--
--   The order of multiple results may not be consistent between
--   lookups. If you require consistent results, apply
--   'Data.List.sort' to the returned list.
--
--   The errors that can occur are the same for all lookups. Namely:
--
--     * Timeout
--
--     * Wrong sequence number (foul play?)
--
--     * Unexpected data in the response
--
--   If an error occurs, you should be able to pattern match on the
--   'DNSError' constructor to determine which of these is the case.
--
--   /Note/: A result of \"no records\" is not considered an
--   error. If you perform, say, an \'AAAA\' lookup for a domain with
--   no such records, the \"success\" result would be @Right []@.
--
--   We perform a successful lookup of \"www.example.com\":
--
--   >>> :set -XOverloadedStrings
--   >>>
--   >>> withLookupConf defaultLookupConf $ \env -> lookupA env "www.example.com"
--   Right [93.184.216.34]
--
--   The only error that we can easily cause is a timeout. We do this
--   by creating and utilizing a 'LookupConf' which has a timeout of
--   one millisecond and a very limited number of retries:
--
--   >>> let badrc = defaultLookupConf { lconfTimeout = 0, lconfRetry = 1 }
--   >>>
--   >>> withLookupConf badrc $ \env -> lookupA env "www.example.com"
--   Left RetryLimitExceeded
--
--   As is the convention, successful results will always be wrapped
--   in a 'Right' while errors will be wrapped in a 'Left'.
--
--   For convenience, you may wish to enable GHC\'s OverloadedStrings
--   extension. This will allow you to avoid calling
--   'Data.ByteString.Char8.pack' on each domain name. See
--   <https://downloads.haskell.org/~ghc/latest/docs/html/users_guide/glasgow_exts.html#overloaded-string-literals>
--   for more information. In the following examples,
--   we assuem this extension is enabled.
--
--   All lookup functions eventually call 'lookupRaw'. See its documentation
--   to understand the concrete lookup behavior.

module DNS.Do53.LookupX (
    lookupA
  , lookupAAAA
  , lookupMX
  , lookupAviaMX
  , lookupAAAAviaMX
  , lookupNS
  , lookupNSAuth
  , lookupTXT
  , lookupSOA
  , lookupPTR
  , lookupRDNS
  , lookupSRV
  ) where

import DNS.Types
import qualified Data.ByteString.Short as Short
import Data.IP
import Data.String (fromString)

import DNS.Do53.Lookup as DNS
import DNS.Do53.Types as DNS

----------------------------------------------------------------

-- | Look up all \'A\' records for the given hostname.
--
--   A straightforward example:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupA env "192.0.2.1.nip.io"
--   Right [192.0.2.1]
--
--   This function will also follow a CNAME and resolve its target if
--   one exists for the queried hostname:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupA env "www.kame.net"
--   Right [210.155.141.200]
--
lookupA :: LookupEnv -> Domain -> IO (Either DNSError [RD_A])
lookupA = lookup' A

-- | Look up all (IPv6) \'AAAA\' records for the given hostname.
--
--   Examples:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupAAAA env "www.wide.ad.jp"
--   Right [2001:200:0:180c:20c:29ff:fec9:9d61]
--
lookupAAAA :: LookupEnv -> Domain -> IO (Either DNSError [RD_AAAA])
lookupAAAA = lookup' AAAA

----------------------------------------------------------------

-- | Look up all \'MX\' records for the given hostname. Two parts
--   constitute an MX record: a hostname , and an integer priority. We
--   therefore return each record as a @('Domain', Int)@.
--
--   In this first example, we look up the MX for the domain \"example.com\".
--   It has an RFC7505 NULL MX (to prevent a deluge of spam from examples
--   posted on the internet).
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupMX env "example.com"
--   Right [RD_MX {mx_preference = 0, mx_exchange = "."}]
--
--
--   The domain \"mew.org\" does however have a single MX:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupMX env "mew.org"
--   Right [RD_MX {mx_preference = 10, mx_exchange = "mail.mew.org."}]
--
--   Also note that all hostnames are returned with a trailing dot to
--   indicate the DNS root.
--
--   However the MX host itself has no need for an MX record, so its MX RRset
--   is empty.  But, \"no results\" is still a successful result.
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupMX env "mail.mew.org"
--   Right []
--
lookupMX :: LookupEnv -> Domain -> IO (Either DNSError [RD_MX])
lookupMX = lookup' MX

-- | Look up all \'MX\' records for the given hostname, and then
--   resolve their hostnames to IPv4 addresses by calling
--   'lookupA'. The priorities are not retained.
--
--   Examples:
--
--   >>> import Data.List (sort)
--   >>> ips <- withLookupConf defaultLookupConf $ \env -> lookupAviaMX env "wide.ad.jp"
--   >>> fmap sort ips
--   Right [203.178.136.30]
--
--   Since there is more than one result, it is necessary to sort the
--   list in order to check for equality.
--
lookupAviaMX :: LookupEnv -> Domain -> IO (Either DNSError [RD_A])
lookupAviaMX rlv dom = lookupXviaMX rlv dom (lookupA rlv)

-- | Look up all \'MX\' records for the given hostname, and then
--   resolve their hostnames to IPv6 addresses by calling
--   'lookupAAAA'. The priorities are not retained.
--
lookupAAAAviaMX :: LookupEnv -> Domain -> IO (Either DNSError [RD_AAAA])
lookupAAAAviaMX rlv dom = lookupXviaMX rlv dom (lookupAAAA rlv)

lookupXviaMX :: LookupEnv
             -> Domain
             -> (Domain -> IO (Either DNSError [a]))
             -> IO (Either DNSError [a])
lookupXviaMX rlv dom func = do
    edps <- lookupMX rlv dom
    case edps of
      -- We have to deconstruct and reconstruct the error so that the
      -- typechecker does not conclude that a ~ (Domain, Int).
      Left err -> return (Left err)
      Right dps -> do
        -- We'll get back a [Either DNSError a] here.
        responses <- mapM (func . mx_exchange) dps
        -- We can use 'sequence' to join all of the Eithers
        -- together. If any of them are (Left _), we'll get a Left
        -- overall. Otherwise, we'll get Right [a].
        let overall = sequence responses
        -- Finally, we use (fmap concat) to concatenate the responses
        -- if there were no errors.
        return $ fmap concat overall

----------------------------------------------------------------

-- | Look up all \'NS\' records for the given hostname. The results
--   are taken from the ANSWER section of the response (as opposed to
--   AUTHORITY). For details, see e.g.
--   <http://www.zytrax.com/books/dns/ch15/>.
--
--   There will typically be more than one name server for a
--   domain. It is therefore extra important to sort the results if
--   you prefer them to be at all deterministic.
--
--   Examples:
--
--   >>> import Data.List (sort)
--   >>> ns <- withLookupConf defaultLookupConf $ \env -> lookupNS env "mew.org"
--   >>> fmap sort ns
--   Right ["ns1.mew.org.","ns2.mew.org."]
--
lookupNS :: LookupEnv -> Domain -> IO (Either DNSError [RD_NS])
lookupNS = lookup' NS

-- | Look up all \'NS\' records for the given hostname. The results
--   are taken from the AUTHORITY section of the response and not the
--   usual ANSWER (use 'lookupNS' for that). For details, see e.g.
--   <http://www.zytrax.com/books/dns/ch15/>.
--
--   There will typically be more than one name server for a
--   domain. It is therefore extra important to sort the results if
--   you prefer them to be at all deterministic.
--
--   For an example, we can look up the nameservers for
--   \"example.com\" from one of the root servers, a.gtld-servers.net,
--   the IP address of which was found beforehand:
--
--   >>> import Data.List (sort)
--   >>> let ri = RCHostName "192.5.6.30" -- a.gtld-servers.net
--   >>> let rc = defaultLookupConf { lconfInfo = ri }
--   >>> ns <- withLookupConf rc $ \env -> lookupNSAuth env "example.com"
--   >>> fmap sort ns
--   Right ["a.iana-servers.net.","b.iana-servers.net."]
--
lookupNSAuth :: LookupEnv -> Domain -> IO (Either DNSError [RD_NS])
lookupNSAuth = lookupAuth' NS

----------------------------------------------------------------

-- | Look up all \'TXT\' records for the given hostname. The results
--   are free-form 'ByteString's.
--
--   Two common uses for \'TXT\' records are
--   <http://en.wikipedia.org/wiki/Sender_Policy_Framework> and
--   <http://en.wikipedia.org/wiki/DomainKeys_Identified_Mail>. As an
--   example, we find the SPF record for \"mew.org\":
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupTXT env "mew.org"
--   Right ["v=spf1 +mx -all"]
--
lookupTXT :: LookupEnv -> Domain -> IO (Either DNSError [RD_TXT])
lookupTXT = lookup' TXT

----------------------------------------------------------------

-- | Look up the \'SOA\' record for the given domain. The result 7-tuple
--   consists of the \'mname\', \'rname\', \'serial\', \'refresh\', \'retry\',
--   \'expire\' and \'minimum\' fields of the SOA record.
--
--   An \@ separator is used between the first and second labels of the
--   \'rname\' field.  Since \'rname\' is an email address, it often contains
--   periods within its first label.  Presently, the trailing period is not
--   removed from the domain part of the \'rname\', but this may change in the
--   future.  Users should be prepared to remove any trailing period before
--   using the \'rname\` as a contact email address.
--
--   >>> soa <- withLookupConf defaultLookupConf $ \env -> lookupSOA env "mew.org"
--   >>> map (\x -> (soa_mname x, soa_rname x)) <$> soa
--   Right [("ns1.mew.org.","kazu@mew.org.")]
--
lookupSOA :: LookupEnv -> Domain -> IO (Either DNSError [RD_SOA])
lookupSOA = lookup' SOA

----------------------------------------------------------------

-- | Look up all \'PTR\' records for the given hostname. To perform a
--   reverse lookup on an IP address, you must first reverse its
--   octets and then append the suffix \".in-addr.arpa.\"
--
--   We look up the PTR associated with the IP address
--   210.130.137.80, i.e., 80.137.130.210.in-addr.arpa:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupPTR env "180.2.232.202.in-addr.arpa"
--   Right ["www.iij.ad.jp."]
--
--   The 'lookupRDNS' function is more suited to this particular task.
--
lookupPTR :: LookupEnv -> Domain -> IO (Either DNSError [RD_PTR])
lookupPTR = lookup' PTR

-- | Convenient wrapper around 'lookupPTR' to perform a reverse lookup
--   on a single IP address.
--
--   We repeat the example from 'lookupPTR', except now we pass the IP
--   address directly:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupRDNS env "202.232.2.180"
--   Right ["www.iij.ad.jp."]
--
lookupRDNS :: LookupEnv -> IPv4 -> IO (Either DNSError [RD_PTR])
lookupRDNS rlv ip = lookupPTR rlv dom
  where
    octets = map (fromString . show ) $ fromIPv4 ip
    reverse_ip = Short.intercalate "." (reverse octets)
    dom = fromRepresentation (reverse_ip <> ".in-addr.arpa")

----------------------------------------------------------------

-- | Look up all \'SRV\' records for the given hostname. SRV records
--   consist (see <https://tools.ietf.org/html/rfc2782>) of the
--   following four fields:
--
--     * Priority (lower is more-preferred)
--
--     * Weight (relative frequency with which to use this record
--       amongst all results with the same priority)
--
--     * Port (the port on which the service is offered)
--
--     * Target (the hostname on which the service is offered)
--
--   The first three are integral, and the target is another DNS
--   hostname. We therefore return a four-tuple
--   @(Int,Int,Int,'Domain')@.
--
--   Examples:
--
--   >>> withLookupConf defaultLookupConf $ \env -> lookupSRV env "_xmpp-server._tcp.jabber.ietf.org"
--   Right [RD_SRV {srv_priority = 5, srv_weight = 0, srv_port = 5269, srv_target = "jabber.ietf.org."}]

-- Though the "jabber.ietf.orgs" SRV record may prove reasonably stable, as
-- with anything else published in DNS it is subject to change.  Also, this
-- example only works when connected to the Internet.  Perhaps the above
-- example should be displayed in a format that is not recognized as a test
-- by "doctest".

lookupSRV :: LookupEnv -> Domain -> IO (Either DNSError [RD_SRV])
lookupSRV = lookup' SRV
