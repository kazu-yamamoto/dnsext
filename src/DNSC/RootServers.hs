module DNSC.RootServers (
  rootServers
  ) where

-- GHC packages
import qualified Data.ByteString.Char8 as B8

-- dns packages
import Network.DNS
  (RData (..), TYPE(NS, A, AAAA), ResourceRecord (ResourceRecord, rrname, rrtype, rdata))
import qualified Network.DNS as DNS

rootServers :: ([ResourceRecord], [ResourceRecord])
rootServers =
  (
    [ mkRR "." NS 3600000 (RD_NS (B8.pack "a.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "b.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "c.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "d.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "e.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "f.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "g.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "h.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "i.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "j.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "k.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "l.root-servers.net."))
    , mkRR "." NS 3600000 (RD_NS (B8.pack "m.root-servers.net."))
    ]
  ,
    [ mkRR "a.root-servers.net." A 3600000 (RD_A (read "198.41.0.4"))
    , mkRR "a.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:503:ba3e::2:30"))
    , mkRR "b.root-servers.net." A 3600000 (RD_A (read "199.9.14.201"))
    , mkRR "b.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:200::b"))
    , mkRR "c.root-servers.net." A 3600000 (RD_A (read "192.33.4.12"))
    , mkRR "c.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:2::c"))
    , mkRR "d.root-servers.net." A 3600000 (RD_A (read "199.7.91.13"))
    , mkRR "d.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:2d::d"))
    , mkRR "e.root-servers.net." A 3600000 (RD_A (read "192.203.230.10"))
    , mkRR "e.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:a8::e"))
    , mkRR "f.root-servers.net." A 3600000 (RD_A (read "192.5.5.241"))
    , mkRR "f.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:2f::f"))
    , mkRR "g.root-servers.net." A 3600000 (RD_A (read "192.112.36.4"))
    , mkRR "g.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:12::d0d"))
    , mkRR "h.root-servers.net." A 3600000 (RD_A (read "198.97.190.53"))
    , mkRR "h.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:1::53"))
    , mkRR "i.root-servers.net." A 3600000 (RD_A (read "192.36.148.17"))
    , mkRR "i.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:7fe::53"))
    , mkRR "j.root-servers.net." A 310698 (RD_A (read "192.58.128.30"))
    , mkRR "j.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:503:c27::2:30"))
    , mkRR "k.root-servers.net." A 3600000 (RD_A (read "193.0.14.129"))
    , mkRR "k.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:7fd::1"))
    , mkRR "l.root-servers.net." A 3600000 (RD_A (read "199.7.83.42"))
    , mkRR "l.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:500:9f::42"))
    , mkRR "m.root-servers.net." A 3600000 (RD_A (read "202.12.27.33"))
    , mkRR "m.root-servers.net." AAAA 3600000 (RD_AAAA (read "2001:dc3::35"))
    ]
  )
  where
    mkRR n ty tt rd = ResourceRecord { rrname = B8.pack n, rrtype = ty, DNS.rrclass = DNS.classIN, DNS.rrttl = tt, rdata = rd }
