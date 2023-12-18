#! /bin/sh

usage() {
    cat<<EOF
Usage: $0

         Build with default params

       $0 {-h|--help}

         Show this help texts

       $0 ghcup DEBIAN_REVISION GHC_VERSION

         Build with ghcup

       $0 haskell HASKELL_IMAGE_TAG

         Build with haskell docker image

       $0 examples

         Show example commands
EOF
}

set -e

GHC_OPTIMIZE=-O
if [ x"$NO_OPTIMIZE" != x ]; then
    GHC_OPTIMIZE='-O0'
fi

[ "$GHC_PARALLEL" != x ] || GHC_PARALLEL=3
[ "$CABAL_PARALLEL" != x ] || CABAL_PARALLEL=3

PRIVKEY_ALG=EC
PRIVKEY_ALGOPT=ec_paramgen_curve:P-256
CHAIN_SUBJ_CN=bowline.example.com


build_with_ghcup() {
    docker buildx build \
           -t bowline:${result_tag} \
           -t bowline:${ghc_version}-${result_tag}-ghcup \
           --build-arg GHC_OPTIMIZE=${GHC_OPTIMIZE} \
           --build-arg GHC_PARALLEL=${GHC_PARALLEL} \
           --build-arg CABAL_PARALLEL=${CABAL_PARALLEL} \
           \
           --build-arg GHC_VERSION=${GHC_VERSION} \
           --build-arg CABAL_VERSION=${CABAL_VERSION} \
           --build-arg DEBIAN_TAG=${DEBIAN_TAG} \
           --build-arg PRIVKEY_ALG=${PRIVKEY_ALG} \
           --build-arg PRIVKEY_ALGOPT=${PRIVKEY_ALGOPT} \
           --build-arg CHAIN_SUBJ_CN=${CHAIN_SUBJ_CN} \
           --build-arg DNSEXT_REV=main \
           -f Dockerfile.ghcup \
           .
}

build_with_haskell() {
    docker buildx build \
           -t bowline:${result_tag} \
           -t bowline:${ghc_version}-${result_tag}-haskell \
           --build-arg GHC_OPTIMIZE=${GHC_OPTIMIZE} \
           --build-arg GHC_PARALLEL=${GHC_PARALLEL} \
           --build-arg CABAL_PARALLEL=${CABAL_PARALLEL} \
           \
           --build-arg HAKELL_TAG=${HAKELL_TAG} \
           --build-arg DEBIAN_TAG=${DEBIAN_TAG} \
           --build-arg PRIVKEY_ALG=${PRIVKEY_ALG} \
           --build-arg PRIVKEY_ALGOPT=${PRIVKEY_ALGOPT} \
           --build-arg CHAIN_SUBJ_CN=${CHAIN_SUBJ_CN} \
           --build-arg DNSEXT_REV=main \
           -f Dockerfile.haskell \
           .
}

## ----------

case "$1" in
    -h|--help)
        usage
        exit 0
        ;;

    '')       ## build with ghcup, default params
        set -x
        ghc_version=9.6.3
        GHC_VERSION=$ghc_version
        CABAL_VERSION=3.10.1.0
        DEBIAN_TAG=bookworm-slim
        result_tag=bookworm

        build_with_ghcup
        ;;

    ghcup)    ## build with ghcup
        set -x
        debian_rev="$2"
        ghc_version="$3"

        case "$ghc_version" in
            9.6.*)
                CABAL_VERSION=3.10.1.0
                ;;
            9.4.*)
                CABAL_VERSION=3.8.1.0
                ;;
            *)
                cat <<EOF
Unsupported GHC version: $ghc_version
EOF
                exit 1
                ;;
        esac

        GHC_VERSION=${ghc_version}
        DEBIAN_TAG=${debian_rev}-slim
        result_tag=${debian_rev}

        build_with_ghcup
        ;;

    haskell)  ## build with haskell docker image
        set -x
        image_tag="$2"

        case "$image_tag" in
            ''|9.4*-slim)
                HAKELL_TAG=9.4.7-slim-buster
                DEBIAN_TAG=buster-slim
                ghc_version=9.4.7
                result_tag=buster

                build_with_haskell
                ;;
            # 9.6*-slim)
            #    HAKELL_TAG=9.6.2-slim-buster ## error, mismatch GHC 9.6.2 with cabal 3.8.1.0
            #    DEBIAN_TAG=buster-slim
            #    result_tag=buster
            #     ;;
            *)
                cat <<EOF
Unsupported haskell image tag: $image_tag
EOF
                ;;
        esac

        build_with_haskell
        ;;

    examples)
        cat <<EOF
$0 ghcup bookworm 9.6.3
$0 haskell 9.4-slim
$0 ghcup bookworm 9.4.7
$0 ghcup bullseye 9.6.3
$0 ghcup bullseye 9.4.7
$0 ghcup buster 9.4.7

# bookworm : Debian 12 - stable release
# bullseye : Debian 11 - old stable
# buster   : Debian 10 - old old stable
EOF
        ;;

    *)
        cat <<EOF
Unknown args: "$@"
EOF
        usage
        exit 1
        ;;
esac
