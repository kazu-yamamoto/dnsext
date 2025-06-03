#! /bin/sh

set -e
set -u

checkout() {
    git clone http://github.com/khibino/dnsext
    (
        cd dnsext
        echo "*** Checkout dnsext       ***"
        echo "*** Directory: $(pwd)"
        git_rev=dist-"${version}"
        [ x"$dev_revision" = x ] || git_rev="$dev_revision"
        git checkout $git_rev
        git --no-pager show --oneline HEAD
        echo "*** Checkout dnsext: done ***"
    )
}

ghc_parallel=-j3
cabal_parallel=--jobs=3

build_bin() {
    cabal v2-update
    (
        cd dnsext

        mkdir -p ${bin_dir}
        echo "*** Configure and Build       ***"
        set -x
        cabal v2-install dnsext-bowline \
               -O1 \
              --enable-split-sections \
              --enable-split-objs \
              --ghc-options="$ghc_parallel +RTS -qg -RTS" \
              $cabal_parallel --install-method=copy \
              --overwrite-policy=always \
              --installdir ${bin_dir}
        set +x
        echo "*** Configure and Build: done ***"
    )
}

build_conf() {
    mkdir -p $conf_dir

    echo "*** Generate conf       ***"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ${conf_dir}/privkey.pem
    openssl req -x509 -key ${conf_dir}/privkey.pem -subj /CN=bowline.example.com -out ${conf_dir}/fullchain.pem

    sed \
        -e 's@^group: .*$@group: nogroup@' \
        -e 's@^#log-file: .*@log-file: log/bowline.log@' \
        -e 's@^#log-timestamp: .*@log-timestamp: yes@' \
        -e 's@^cache-size: .*$@cache-size: 2097152@' \
        -e 's@^cert-file: .*$@cert-file: etc/fullchain.pem@' \
        -e 's@^key-file: .*$@key-file: etc/privkey.pem@' \
        -e 's@^cachers: .*$@cacher: 1@' \
        -e 's@^workers: .*$@workers: 256@' \
        -e 's@^h2c: .*@h2c: no@' \
        -e 's@^monitor-stdio: .*@monitor-stdio: no@' \
        < dnsext/dnsext-bowline/bowline/bowline.conf > ${conf_dir}/bowline.conf
    echo "*** Generate conf: done ***"
}

build_meta() {
    mkdir -p $dest_prefix

    echo "*** Generate metadata       ***"

    cp -a ${base_dir}/template/* ${dest_prefix}/

    echo "*** Generate metadata: done ***"
}

##-----

base_dir=$(pwd)
work_dir=${base_dir}/work

with_workdir() {
    mkdir -p ${work_dir}
    (
        cd $work_dir
        "$@"
    )
}

with_srcdir() {
    (
        cd ${src_base}
        "$@"
    )
}

set_version() {
    if [ x"$1" = x ]; then
        echo "VERSION required"
        usage
        exit 1
    fi
    version="$1"
}

set_vars() {
    set_version "$1"

    dest_prefix=${work_dir}/bowline-${version}
    meta_dir=${dest_prefix}/debian
    conf_dir=${dest_prefix}/etc
    bin_dir=${dest_prefix}/bin

    src_base=${dest_prefix}
}

##-----

setup_data() {
    build_meta
    build_conf
}

setup_build_src() {
    checkout
    setup_data
    build_bin
}

build_pkgs() {
    DEB_BUILD_OPTIONS=noautodbgsym
    export DEB_BUILD_OPTIONS
    debuild -uc -us
    lintian -i ../bowline_${version}_amd64.changes
}

##-----

usage() {
        cat <<EOF
Usage: $0 sdeps
       $0 psrc VERSION
       $0 clean

       $0 checkout VERSION
       $0 data VERSION
EOF
}

[ ! -r ./params ] || . ./params

case "$1" in
    sdeps)
        sudo apt-get install libz-dev openssl
        ;;

    checkout)
        shift
        set_version $1
        with_workdir checkout
        ;;

    data)
        shift
        set_vars $1
        with_workdir setup_data
        ;;

    psrc)
        shift
        set_vars $1
        with_workdir setup_build_src
        ;;

    pkgs)
        shift
        set_vars $1
        with_srcdir build_pkgs
        ;;

    all)
        shift
        set_vars $1
        with_workdir setup_build_src
        with_srcdir build_pkgs
        ;;

    clean)
        set -x
        rm -fr ${work_dir}
        ghc_ver=$(ghc --numeric-version)
        prefix_list="
$HOME/.cabal/store/
$HOME/.local/state/cabal/store/
"
        for prefix in $prefix_list ; do
            store=${prefix}/ghc-${ghc_ver}
            if [ -d $store ] ; then
                rm -r $store
            fi
        done
        ghc-pkg recache --user
        ;;

    *)
        usage
        ;;
esac
