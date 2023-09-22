cab delete -r dnsext-types
for pkg in dnsext-types dnsext-dnssec dnsext-svcb dnsext-utils dnsext-do53 dnsext-dox dnsext-iterative
do
(cd $pkg; cab clean; cab install)
done

(cd dnsext-bowline; cab install -d; cab clean; cab conf; cab build)
