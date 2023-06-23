![GitHub Actions status](https://github.com/kazu-yamamoto/dnsext/workflows/Haskell%20CI/badge.svg)

# Extensible DNS libraries written purely in Haskell

This is a new series of DNS libraries based on the experience of the [dns](https://github.com/kazu-yamamoto/dns) library in Haskell. The dns library has two flaws:

- Resource records are not extensible
- Resource records are not friendly to caching

Resource records are implemented as a sum type. The third party library cannot extend them. The only way to extend them is to send a pull request to the dns library.

Some resource records use `ByteString` internally. So, if they are cached for a long time, fragmentation happens.

This new library uses typeclasses to extend resource records and uses `ShortByteString` in them.

## `bowline`, a full resolver server

`dnsext-full-resolver` provides a server of full resolver, called `bowline`.

## `dug`, a stub/full resolver command

`dnsext-full-resolver` also provides dig-like command called `dug`.

SVBC example: if `-d auto` is specified, `dug` obtains the SVCB record first and resolves the target RR via DNS over X:

```
% dug @1.1.1.1 www.iij.ad.jp --demo -d auto
query "_dns.resolver.arpa." SVCB to 1.1.1.1#53/UDP
[RD_SVCB {svcb_priority = 1, svcb_target = "one.one.one.one.", svcb_params = [alpn=["h2"], port=443, ipv4hint=[1.1.1.1,1.0.0.1], ipv6hint=[2606:4700:4700::1111,2606:4700:4700::1001], dohpath="/dns-query{?dns}"]},RD_SVCB {svcb_priority = 2, svcb_target = "one.one.one.one.", svcb_params = [alpn=["dot"], port=853, ipv4hint=[1.1.1.1,1.0.0.1], ipv6hint=[2606:4700:4700::1111,2606:4700:4700::1001]]}]
query "www.iij.ad.jp." A to 1.1.1.1#443/HTTP/2
query "www.iij.ad.jp." A to 2606:4700:4700::1111#443/HTTP/2
query "www.iij.ad.jp." A to 2606:4700:4700::1001#443/HTTP/2
query "www.iij.ad.jp." A to 1.0.0.1#443/HTTP/2
query "www.iij.ad.jp." A to 1.1.1.1#443/HTTP/2: win
;; 1.1.1.1#443/HTTP/2, Tx:42bytes, Rx:58bytes, 135usec

;; HEADER SECTION:
;Standard query, NoError, id: 2859
;Flags: Recursion Desired, Recursion Available


;; OPTIONAL PSEUDO SECTION:
;UDP: 1232, Data:[]

;; QUESTION SECTION:
;www.iij.ad.jp.		IN	A

;; ANSWER SECTION:
www.iij.ad.jp.	98(1 min)	IN	A	202.232.2.180

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:
```

Full resolve example: if `-i` is specified, `dug` does iterative queries using the logic of the full resolver.

```
% dug www.iij.ad.jp --demo -i
resolve-just: dc=0, ("www.iij.ad.jp.",A)
root-server addresses for priming: 198.97.190.53 199.7.83.42 199.7.91.13 199.9.14.201
query "." DNSKEY to 198.97.190.53#53/UDP
query "." DNSKEY to 199.7.83.42#53/UDP
query "." DNSKEY to 199.7.91.13#53/UDP
query "." DNSKEY to 199.9.14.201#53/UDP
query "." DNSKEY to 199.7.91.13#53/UDP: win
query "." NS to 198.97.190.53#53/UDP
query "." NS to 199.7.83.42#53/UDP
query "." NS to 199.7.91.13#53/UDP
query "." NS to 199.9.14.201#53/UDP
query "." NS to 198.97.190.53#53/UDP: win
root-priming: verification success - RRSIG of NS: "."
	"a.root-servers.net." ["198.41.0.4","2001:503:ba3e::2:30"]
	"b.root-servers.net." ["199.9.14.201","2001:500:200::b"]
	"c.root-servers.net." ["192.33.4.12","2001:500:2::c"]
	"d.root-servers.net." ["199.7.91.13","2001:500:2d::d"]
	"e.root-servers.net." ["192.203.230.10","2001:500:a8::e"]
	"f.root-servers.net." ["192.5.5.241","2001:500:2f::f"]
	"g.root-servers.net." ["192.112.36.4","2001:500:12::d0d"]
	"h.root-servers.net." ["198.97.190.53","2001:500:1::53"]
	"i.root-servers.net." ["192.36.148.17","2001:7fe::53"]
	"j.root-servers.net." ["192.58.128.30","2001:503:c27::2:30"]
	"k.root-servers.net." ["193.0.14.129","2001:7fd::1"]
	"l.root-servers.net." ["199.7.83.42","2001:500:9f::42"]
	"m.root-servers.net." ["202.12.27.33","2001:dc3::35"]
zone: ".":
	"a.root-servers.net." ["198.41.0.4","2001:503:ba3e::2:30"]
	"b.root-servers.net." ["199.9.14.201","2001:500:200::b"]
	"c.root-servers.net." ["192.33.4.12","2001:500:2::c"]
	"d.root-servers.net." ["199.7.91.13","2001:500:2d::d"]
	"e.root-servers.net." ["192.203.230.10","2001:500:a8::e"]
	"f.root-servers.net." ["192.5.5.241","2001:500:2f::f"]
	"g.root-servers.net." ["192.112.36.4","2001:500:12::d0d"]
	"h.root-servers.net." ["198.97.190.53","2001:500:1::53"]
	"i.root-servers.net." ["192.36.148.17","2001:7fe::53"]
	"j.root-servers.net." ["192.58.128.30","2001:503:c27::2:30"]
	"k.root-servers.net." ["193.0.14.129","2001:7fd::1"]
	"l.root-servers.net." ["199.7.83.42","2001:500:9f::42"]
	"m.root-servers.net." ["202.12.27.33","2001:dc3::35"]
iterative: query ("jp.",A) with selected addresses: 2001:500:1::53 2001:500:2::c 2001:500:12::d0d 2001:500:2d::d
query "jp." A to 2001:500:1::53#53/UDP
query "jp." A to 2001:500:2::c#53/UDP
query "jp." A to 2001:500:12::d0d#53/UDP
query "jp." A to 2001:500:2d::d#53/UDP
query "jp." A to 2001:500:2d::d#53/UDP: win
delegationWithCache: "." -> "jp.", delegation - verification success - RRSIG of DS
	"a.dns.jp." ["203.119.1.1","2001:dc4::1"]
	"b.dns.jp." ["202.12.30.131","2001:dc2::1"]
	"c.dns.jp." ["156.154.100.5","2001:502:ad09::5"]
	"d.dns.jp." ["210.138.175.244","2001:240::53"]
	"e.dns.jp." ["192.50.43.53","2001:200:c000::35"]
	"f.dns.jp." ["150.100.6.8","2001:2f8:0:100::153"]
	"g.dns.jp." ["203.119.40.1"]
	"h.dns.jp." ["161.232.72.25","2a01:8840:1bc::25"]
query "jp." DNSKEY to 2001:502:ad09::5#53/UDP
query "jp." DNSKEY to 2001:dc2::1#53/UDP
query "jp." DNSKEY to 2001:dc4::1#53/UDP
query "jp." DNSKEY to 2a01:8840:1bc::25#53/UDP
query "jp." DNSKEY to 2001:dc4::1#53/UDP: win
zone: "jp.":
	"a.dns.jp." ["203.119.1.1","2001:dc4::1"]
	"b.dns.jp." ["202.12.30.131","2001:dc2::1"]
	"c.dns.jp." ["156.154.100.5","2001:502:ad09::5"]
	"d.dns.jp." ["210.138.175.244","2001:240::53"]
	"e.dns.jp." ["192.50.43.53","2001:200:c000::35"]
	"f.dns.jp." ["150.100.6.8","2001:2f8:0:100::153"]
	"g.dns.jp." ["203.119.40.1"]
	"h.dns.jp." ["161.232.72.25","2a01:8840:1bc::25"]
iterative: query ("ad.jp.",A) with selected addresses: 2001:502:ad09::5 2001:dc2::1 2001:dc4::1 2a01:8840:1bc::25
query "ad.jp." A to 2001:502:ad09::5#53/UDP
query "ad.jp." A to 2001:dc2::1#53/UDP
query "ad.jp." A to 2001:dc4::1#53/UDP
query "ad.jp." A to 2a01:8840:1bc::25#53/UDP
query "ad.jp." A to 2001:dc4::1#53/UDP: win
delegationWithCache: "jp." -> "ad.jp.", no delegation
zone: "jp.":
	"a.dns.jp." ["203.119.1.1","2001:dc4::1"]
	"b.dns.jp." ["202.12.30.131","2001:dc2::1"]
	"c.dns.jp." ["156.154.100.5","2001:502:ad09::5"]
	"d.dns.jp." ["210.138.175.244","2001:240::53"]
	"e.dns.jp." ["192.50.43.53","2001:200:c000::35"]
	"f.dns.jp." ["150.100.6.8","2001:2f8:0:100::153"]
	"g.dns.jp." ["203.119.40.1"]
	"h.dns.jp." ["161.232.72.25","2a01:8840:1bc::25"]
iterative: query ("iij.ad.jp.",A) with selected addresses: 2001:240::53 2001:2f8:0:100::153 2001:502:ad09::5 2001:dc2::1
query "iij.ad.jp." A to 2001:240::53#53/UDP
query "iij.ad.jp." A to 2001:2f8:0:100::153#53/UDP
query "iij.ad.jp." A to 2001:502:ad09::5#53/UDP
query "iij.ad.jp." A to 2001:dc2::1#53/UDP
query "iij.ad.jp." A to 2001:240::53#53/UDP: win
delegationWithCache: "jp." -> "iij.ad.jp.", delegation - verification success - RRSIG of DS
	"dns0.iij.ad.jp." ["210.130.0.5","2001:240::105"]
	"dns1.iij.ad.jp." ["210.130.1.5","2001:240::115"]
query "iij.ad.jp." DNSKEY to 210.130.0.5#53/UDP
query "iij.ad.jp." DNSKEY to 210.130.1.5#53/UDP
query "iij.ad.jp." DNSKEY to 2001:240::105#53/UDP
query "iij.ad.jp." DNSKEY to 2001:240::115#53/UDP
query "iij.ad.jp." DNSKEY to 2001:240::105#53/UDP: win
zone: "iij.ad.jp.":
	"dns0.iij.ad.jp." ["210.130.0.5","2001:240::105"]
	"dns1.iij.ad.jp." ["210.130.1.5","2001:240::115"]
iterative: query ("www.iij.ad.jp.",A) with selected addresses: 210.130.0.5 210.130.1.5 2001:240::105 2001:240::115
query "www.iij.ad.jp." A to 210.130.0.5#53/UDP
query "www.iij.ad.jp." A to 210.130.1.5#53/UDP
query "www.iij.ad.jp." A to 2001:240::105#53/UDP
query "www.iij.ad.jp." A to 2001:240::115#53/UDP
query "www.iij.ad.jp." A to 2001:240::105#53/UDP: win
delegationWithCache: "iij.ad.jp." -> "www.iij.ad.jp.", no delegation
resolve-just: query ("www.iij.ad.jp.",A) selected addresses: 210.130.0.5 210.130.1.5 2001:240::105 2001:240::115
query "www.iij.ad.jp." A to 210.130.0.5#53/UDP
query "www.iij.ad.jp." A to 210.130.1.5#53/UDP
query "www.iij.ad.jp." A to 2001:240::105#53/UDP
query "www.iij.ad.jp." A to 2001:240::115#53/UDP
query "www.iij.ad.jp." A to 2001:240::105#53/UDP: win
verification success - RRSIG of "www.iij.ad.jp." A
;; 182usec

;; HEADER SECTION:
;Standard query, NoError, id: 0
;Flags: Recursion Desired, Recursion Available


;; QUESTION SECTION:
;www.iij.ad.jp.		IN	A

;; ANSWER SECTION:
www.iij.ad.jp.	300(5 mins)	IN	A	202.232.2.180

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:
```