module Operation where

import qualified Data.ByteString.Char8 as B8
import Text.Read (readMaybe)

import Data.IP (IP (..))
import DNS.Types (TYPE, DNSError, DNSMessage)
import DNS.IO.Types (QueryControls)
import DNS.IO.Resolver (
   ResolvConf (resolvInfo, resolvTimeout, resolvRetry, resolvQueryControls))
import qualified DNS.Types as DNS
import qualified DNS.IO as DNS
import qualified DNS.IO.Resolver as DNS
import qualified DNS.IO.Lookup as DNS
import System.Random (randomRIO)


type HostName = String

operate :: Maybe HostName -> HostName -> TYPE -> QueryControls -> IO (Either DNSError DNSMessage)
operate server domain type_ controls = do
  conf <- getCustomConf server controls
  operate_ conf domain type_

operate_ :: ResolvConf -> HostName -> TYPE -> IO (Either DNSError DNSMessage)
operate_ conf name typ = do
  rs <- DNS.makeResolvSeed conf
  DNS.withResolver rs $ \resolver -> DNS.lookupRaw resolver (DNS.byteStringToDomain $ B8.pack name) typ

getCustomConf :: Maybe HostName -> QueryControls -> IO ResolvConf
getCustomConf mayServer controls = do
  let resolveServer server c = do
        ip <- resolve server
        -- print ip
        return $ setServer ip c

  maybe return resolveServer mayServer
    DNS.defaultResolvConf
    { resolvTimeout = 5 * 1000 * 1000
    , resolvRetry = 2
    , resolvQueryControls = controls
    }
  where
    resolve :: String -> IO IP
    resolve sname =
      maybe (queryName sname) return $ readMaybe sname

    queryName :: String -> IO IP
    queryName sname = do
      rs <- DNS.makeResolvSeed DNS.defaultResolvConf
      as <- DNS.withResolver rs $ \resolver -> do
        let bn = B8.pack sname
        eA  <- DNS.lookupA    resolver $ DNS.byteStringToDomain bn
        eQA <- DNS.lookupAAAA resolver $ DNS.byteStringToDomain bn
        let catAs = do
              as  <- eA
              qas <- eQA
              return $ map (IPv4 . DNS.a_ipv4) as ++ map (IPv6 . DNS.aaaa_ipv6) qas
        either (fail . show) return catAs
      ix <- randomRIO (0, length as - 1)
      return $ as !! ix

    setServer ip c = c { resolvInfo = DNS.RCHostName $ show ip }
