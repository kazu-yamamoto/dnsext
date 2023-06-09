{-# LANGUAGE OverloadedStrings #-}

module DNS.Cache.RootServers (
    rootServers,
) where

-- dns packages
import DNS.Types (
    ResourceRecord (ResourceRecord, rdata, rrname, rrtype),
    TYPE (A, AAAA, NS),
    rd_a,
    rd_aaaa,
    rd_ns,
 )
import qualified DNS.Types as DNS

rootServers :: ([ResourceRecord], [ResourceRecord])
rootServers =
    (
        [ mkRR "." NS 3600000 (rd_ns "a.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "b.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "c.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "d.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "e.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "f.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "g.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "h.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "i.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "j.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "k.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "l.root-servers.net.")
        , mkRR "." NS 3600000 (rd_ns "m.root-servers.net.")
        ]
    ,
        [ mkRR "a.root-servers.net." A 3600000 (rd_a "198.41.0.4")
        , mkRR "a.root-servers.net." AAAA 3600000 (rd_aaaa "2001:503:ba3e::2:30")
        , mkRR "b.root-servers.net." A 3600000 (rd_a "199.9.14.201")
        , mkRR "b.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:200::b")
        , mkRR "c.root-servers.net." A 3600000 (rd_a "192.33.4.12")
        , mkRR "c.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:2::c")
        , mkRR "d.root-servers.net." A 3600000 (rd_a "199.7.91.13")
        , mkRR "d.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:2d::d")
        , mkRR "e.root-servers.net." A 3600000 (rd_a "192.203.230.10")
        , mkRR "e.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:a8::e")
        , mkRR "f.root-servers.net." A 3600000 (rd_a "192.5.5.241")
        , mkRR "f.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:2f::f")
        , mkRR "g.root-servers.net." A 3600000 (rd_a "192.112.36.4")
        , mkRR "g.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:12::d0d")
        , mkRR "h.root-servers.net." A 3600000 (rd_a "198.97.190.53")
        , mkRR "h.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:1::53")
        , mkRR "i.root-servers.net." A 3600000 (rd_a "192.36.148.17")
        , mkRR "i.root-servers.net." AAAA 3600000 (rd_aaaa "2001:7fe::53")
        , mkRR "j.root-servers.net." A 3600000 (rd_a "192.58.128.30")
        , mkRR "j.root-servers.net." AAAA 3600000 (rd_aaaa "2001:503:c27::2:30")
        , mkRR "k.root-servers.net." A 3600000 (rd_a "193.0.14.129")
        , mkRR "k.root-servers.net." AAAA 3600000 (rd_aaaa "2001:7fd::1")
        , mkRR "l.root-servers.net." A 3600000 (rd_a "199.7.83.42")
        , mkRR "l.root-servers.net." AAAA 3600000 (rd_aaaa "2001:500:9f::42")
        , mkRR "m.root-servers.net." A 3600000 (rd_a "202.12.27.33")
        , mkRR "m.root-servers.net." AAAA 3600000 (rd_aaaa "2001:dc3::35")
        ]
    )
  where
    mkRR n ty tt rd =
        ResourceRecord
            { rrname = n
            , rrtype = ty
            , DNS.rrclass = DNS.classIN
            , DNS.rrttl = tt
            , rdata = rd
            }
