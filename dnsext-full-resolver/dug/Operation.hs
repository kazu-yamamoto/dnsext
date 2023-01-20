module Operation where

import Text.Read (readMaybe)

import Data.IP (IP (..))
import DNS.Types (TYPE, DNSError, DNSMessage)
import DNS.Do53.Client (QueryControls,
               LookupConf (lconfInfo, lconfTimeout, lconfRetry, lconfQueryControls))
import qualified DNS.Do53.Client as DNS
import qualified DNS.Types as DNS
import System.Random (randomRIO)


type HostName = String

operate :: Maybe HostName -> HostName -> TYPE -> QueryControls -> IO (Either DNSError DNSMessage)
operate server domain type_ controls = do
  conf <- getCustomConf server controls
  operate_ conf domain type_

operate_ :: LookupConf -> HostName -> TYPE -> IO (Either DNSError DNSMessage)
operate_ conf name typ = DNS.withLookupConf conf $ \seeds -> do
    let q = DNS.Question (DNS.fromRepresentation name) typ DNS.classIN
    DNS.lookupRaw seeds q

getCustomConf :: Maybe HostName -> QueryControls -> IO LookupConf
getCustomConf mayServer controls = do
  let resolveServer server c = do
        ip <- resolve server
        -- print ip
        return $ setServer ip c

  maybe return resolveServer mayServer
    DNS.defaultLookupConf
    { lconfTimeout = 5 * 1000 * 1000
    , lconfRetry = 2
    , lconfQueryControls = controls
    }
  where
    resolve :: String -> IO IP
    resolve sname =
      maybe (queryName sname) return $ readMaybe sname

    queryName :: String -> IO IP
    queryName sname = do
      as <- DNS.withLookupConf DNS.defaultLookupConf $ \seeds -> do
        let dom = DNS.fromRepresentation sname
        eA  <- DNS.lookupA    seeds dom
        eQA <- DNS.lookupAAAA seeds dom
        let catAs = do
              as  <- eA
              qas <- eQA
              return $ map (IPv4 . DNS.a_ipv4) as ++ map (IPv6 . DNS.aaaa_ipv6) qas
        either (fail . show) return catAs
      ix <- randomRIO (0, length as - 1)
      return $ as !! ix

    setServer ip c = c { lconfInfo = DNS.RCHostName $ show ip }
