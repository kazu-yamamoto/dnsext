for pkg in dnsext-types dnsext-dnssec dnsext-utils dnsext-do53 dnsext-svcb dnsext-dox dnsext-iterative dnsext-bowline
do
(cd $pkg; cabal format ${pkg}.cabal)
done
