#! /bin/sh

set_ports() {
    mode="$1"
    case $mode in
        root)
            udp_port=53
            tcp_port=53
            tls_port=853
            h2c_port=80
            h2_port=443
            h3_port=443
            quic_port=853
            ;;
        *)
            udp_port=1053
            tcp_port=1053
            tls_port=1853
            h2c_port=1080
            h2_port=1443
            h3_port=1443
            quic_port=1853
            ;;
    esac
}

check() {
    local proto="$1"
    local addr="$2"

    case "$proto" in
        udp)
            set -x
            dug @${addr} $domain $type -p $udp_port -d udp
            ;;

        tcp)
            set -x
            dug @${addr} $domain $type -p $tcp_port -d tcp
            ;;

        tls|dot)
            set -x
            dug @${addr} $domain $type -p $tls_port -d dot
            ;;

        h2c|doh2c)
            set -x
            dug @${addr} $domain $type -p $h2c_port -d h2c
            ;;

        h2|doh2)
            set -x
            dug @${addr} $domain $type -p $h2_port -d h2
            ;;

        h3|doh3)
            set -x
            dug @${addr} $domain $type -p $h3_port -d h3
            ;;

        quic|doq)
            set -x
            dug @${addr} $domain $type -p $quic_port -d doq
            ;;

        all)
            for p in udp tcp h2c h2 h3 tls quic ; do
                check $p $addr
            done
            ;;

        *)
            cat <<EOF
Usage: $0 {all|udp|tcp|tls|dot|h2c|doh2c|h2|doh2|h3|doh3|quic|dot} [root|user]
EOF
            exit 1
            ;;
    esac
}

proto="$1"

mode="$2"
if [ x"$mode" = x ]; then
    mode="root"
fi

set_ports "${mode}"

domain=iij.ad.jp.
type=A

for addr in 127.0.0.1 ; do
    check $proto $addr
done
