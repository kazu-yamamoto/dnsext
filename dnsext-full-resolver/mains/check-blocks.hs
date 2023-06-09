import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString.Char8 as B8
import Numeric (showHex)

import Data.IP (
    AddrRange (addr, mlen),
    IP (IPv4, IPv6),
    IPRange (IPv4Range, IPv6Range),
    fromIPv4,
    fromIPv6b,
 )
import Network.DNS (
    DNSError,
    DNSMessage,
    ResolvConf (..),
    ResolvSeed,
    TYPE (PTR),
 )
import qualified Network.DNS as DNS

{- special IP blocks to check -}
blocks :: [(String, String)]
blocks =
    {- IPv4 Special-Purpose Address Registry Entries
       https://datatracker.ietf.org/doc/html/rfc6890.html#section-2.2.2 -}
    [ ("0.0.0.0/8", "This host on this network")
    , ("10.0.0.0/8", "Private-Use")
    , ("100.64.0.0/10", "Shared Address Space")
    , ("127.0.0.0/8", "Loopback")
    , ("169.254.0.0/16", "Link Local")
    , ("172.16.0.0/12", "Private-Use")
    , ("192.0.0.0/24", "IETF Protocol Assignments")
    , ("192.0.0.0/29", "DS-Lite")
    , ("192.0.2.0/24", "Documentation (TEST-NET-1)")
    , ("192.88.99.0/24", "6to4 Relay Anycast")
    , ("192.168.0.0/16", "Private-Use")
    , ("198.18.0.0/15", "Benchmarking")
    , ("198.51.100.0/24", "Documentation (TEST-NET-2)")
    , ("203.0.113.0/24", "Documentation (TEST-NET-3)")
    , ("240.0.0.0/4 ", "Reserved")
    , ("255.255.255.255/32", "Limited Broadcast")
    ]
        ++
        {- IPv6 Special-Purpose Address Registry Entries
           https://datatracker.ietf.org/doc/html/rfc6890.html#section-2.2.3 -}
        [ ("::1/128", "Loopback Address")
        , ("::/128", "Unspecified Address")
        , ("64:ff9b::/96", "IPv4-IPv6 Translat.")
        , ("::ffff:0:0/96", "IPv4-mapped Address")
        , ("100::/64", "Discard-Only Address Block")
        , ("2001::/23", "IETF Protocol Assignments")
        , ("2001::/32", "TEREDO")
        , ("2001:2::/48", "Benchmarking")
        , ("2001:db8::/32", "Documentation")
        , ("2001:10::/28", "ORCHID")
        , ("2002::/16", "6to4")
        , ("fc00::/7", "Unique-Local")
        , ("fe80::/10", "Linked-Scoped Unicast")
        ]

ipRevDomain :: IP -> String
ipRevDomain ip = case ip of
    IPv4 v4 -> rev4 v4
    IPv6 v6 -> rev6 v6
  where
    rev4 v4 = concatMap ((++ ".") . show) (reverse $ fromIPv4 v4) ++ "in-addr.arpa."
    rev6 v6 =
        concat
            [showHex h [] ++ "." | byte <- reverse $ fromIPv6b v6, h <- e2fRev byte]
            ++ "ip6.arpa."
      where
        e2fRev byte = [byte .&. 0x0f, byte `shiftR` 4]

localRS :: IO ResolvSeed
localRS =
    DNS.makeResolvSeed
        DNS.defaultResolvConf
            { resolvInfo = DNS.RCHostName "127.0.0.1"
            , resolvTimeout = 5 * 1000 * 1000
            , resolvRetry = 1
            , resolvQueryControls = DNS.rdFlag DNS.FlagSet
            }

withRange :: ((IPRange, IP, String) -> a) -> (String, IPRange) -> a
withRange handler (title, block) = handler $ dispatch block
  where
    dispatch (IPv4Range blk4) = mkInput (IPv4 $ addr blk4) (2 ^ (32 - mlen blk4) :: Int)
    dispatch (IPv6Range blk6) = mkInput (IPv6 $ addr blk6) (2 ^ (128 - mlen blk6) :: Int)
    mkInput baddr spaceSize = (block, selectIP spaceSize baddr, title)
    selectIP spaceSize baddr
        | spaceSize == 1 = baddr
        | spaceSize == 2 = succ baddr
        | otherwise = succ $ succ baddr

queryPTR :: ResolvSeed -> IP -> IO (Either DNSError DNSMessage)
queryPTR rs revIP = DNS.withResolver rs $ \res -> DNS.lookupRaw res (B8.pack $ ipRevDomain revIP) PTR

printQueryResult :: ResolvSeed -> (IPRange, IP, String) -> IO ()
printQueryResult rs (block, revIP, title) = do
    let showLine (c, x) = unwords [c, map unSpace title, show block, show revIP, x]
        result msg = case DNS.authority msg of
            [] -> [showLine noAuthority]
            as -> map (showLine . rdataPair . DNS.rdata) as
    mapM_ putStrLn . either (const [showLine dnsError]) result =<< queryPTR rs revIP
  where
    unSpace ' ' = '_'
    unSpace x = x

rdataPair :: DNS.RData -> (String, String)
rdataPair rd = (codeFromRData rd, show rd)
  where
    {- code list
    -- 0 : unknown
    -- 1 : known domain
    -- 2 : no SOA
    -- 3 : no authority
    -- 4 : dns error
     -}
    codeFromRData (DNS.RD_SOA dom _ _ _ _ _ _)
        | any (`B8.isSuffixOf` dom) knownDomains = "1"
        | otherwise = "0"
    codeFromRData _ = "2"
    knownDomains =
        map
            B8.pack
            ["arin.net.", "in-addr-servers.arpa.", "ip6-servers.arpa.", "6to4.nro.net."]

noAuthority :: (String, String)
noAuthority = ("3", "")
dnsError :: (String, String)
dnsError = ("4", "")

main :: IO ()
main = do
    rs <- localRS
    mapM_ (withRange $ printQueryResult rs)
        =<< sequence
            [ (,) title <$> readIO blk
            | (blk, title) <- blocks
            ]
