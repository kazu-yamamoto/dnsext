module DigLike.Operation where

import qualified Data.ByteString.Char8 as B8
import Text.Read (readMaybe)

import Data.IP (IP (..))
import Network.DNS
  (TYPE, DNSError, DNSMessage, QueryControls,
   ResolvConf (resolvInfo, resolvTimeout, resolvRetry, resolvQueryControls))
import qualified Network.DNS as DNS
import System.Random (randomRIO)


type HostName = String

operate :: Maybe HostName -> HostName -> TYPE -> QueryControls -> IO (Either DNSError DNSMessage)
operate server domain type_ controls = do
  conf <- getCustomConf server controls
  operate_ conf domain type_

operate_ :: ResolvConf -> HostName -> TYPE -> IO (Either DNSError DNSMessage)
operate_ conf name typ = do
  rs <- DNS.makeResolvSeed conf
  DNS.withResolver rs $ \resolver -> DNS.lookupRaw resolver (B8.pack name) typ

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
        eA  <- DNS.lookupA resolver bn
        eQA <- DNS.lookupAAAA resolver bn
        let catAs = do
              as  <- eA
              qas <- eQA
              return $ map IPv4 as ++ map IPv6 qas
        either (fail . show) return catAs
      ix <- randomRIO (0, length as - 1)
      return $ as !! ix

    setServer ip c = c { resolvInfo = DNS.RCHostName $ show ip }
