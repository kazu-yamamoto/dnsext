#! /bin/sh

usage() {
        cat <<EOF
Usage: $0 -x [REVISION_TO_BUILD [CLONE_URL]]

         Execute build process

       $0 {-h|--help}

         Show this help texts

EOF
}

set -e

[ ! -r ./params ] || . ./params

GHC_OPTIMIZE=-O
if [ x"$NO_OPTIMIZE" != x ]; then
    GHC_OPTIMIZE='-O0'
fi

[ x"$GHC_PARALLEL" != x ] || GHC_PARALLEL=3
[ x"$CABAL_PARALLEL" != x ] || CABAL_PARALLEL=3

PRIVKEY_ALG=EC
PRIVKEY_ALGOPT=ec_paramgen_curve:P-256
CHAIN_SUBJ_CN=bowline.example.com


build_with_ghcup() {
    tag_ghcup=bowline:${ghc_version}-${result_tag_debian}-ghcup
    docker buildx build \
           -t ${tag_ghcup} \
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
           --build-arg CLONE_URL=${CLONE_URL} \
           --build-arg DNSEXT_REV=${DNSEXT_REV} \
           -f Dockerfile.ghcup \
           .

    if [ "${ghc_version}" = 9.6.4 ]; then
        docker image tag "${tag_ghcup}" bowline:${result_tag_debian}
        if [ "${result_tag_debian}" = bookworm ]; then
            docker image tag bowline:${result_tag_debian} bowline:latest
        fi
    fi
}

build_with_haskell() {
    docker buildx build \
           -t bowline:${ghc_version}-${result_tag_debian}-haskell \
           --build-arg GHC_OPTIMIZE=${GHC_OPTIMIZE} \
           --build-arg GHC_PARALLEL=${GHC_PARALLEL} \
           --build-arg CABAL_PARALLEL=${CABAL_PARALLEL} \
           \
           --build-arg HAKELL_TAG=${HAKELL_TAG} \
           --build-arg DEBIAN_TAG=${DEBIAN_TAG} \
           --build-arg PRIVKEY_ALG=${PRIVKEY_ALG} \
           --build-arg PRIVKEY_ALGOPT=${PRIVKEY_ALGOPT} \
           --build-arg CHAIN_SUBJ_CN=${CHAIN_SUBJ_CN} \
           --build-arg CLONE_URL=${CLONE_URL} \
           --build-arg DNSEXT_REV=${DNSEXT_REV} \
           -f Dockerfile.haskell \
           .
}

## ----------

case "$1" in
    -h|--help)
        usage
        exit 0
        ;;

    -x)
        ;;

    *)
        usage
        exit 1
        ;;
esac
shift

set -x
DNSEXT_REV="$1"
[ x"$DNSEXT_REV" != x ] || DNSEXT_REV=dist-docker

CLONE_URL="$2"
[ x"$CLONE_URL" != x ] || CLONE_URL=http://github.com/kazu-yamamoto/dnsext
set +x

## ----------

[ x"$BOWLINE_BUILD_METHOD" != x ] || BOWLINE_BUILD_METHOD=ghcup

case "$BOWLINE_BUILD_METHOD" in
    ghcup)
        [ x"$GHC_VERSION" != x ] || GHC_VERSION=9.6.4
        [ x"$DEBIAN_REVISON" != x ] || DEBIAN_REVISON=bookworm
        #--
        set -x
        debian_rev="$DEBIAN_REVISON"
        ghc_version="$GHC_VERSION"
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
        DEBIAN_TAG=${debian_rev}-slim
        result_tag_debian=${debian_rev}

        build_with_ghcup
        ;;

    haskell)
        [ x"$GHC_VERSION" != x ] || GHC_VERSION=9.4.8
        #--
        set -x
        HAKELL_TAG=${GHC_VERSION}-slim-buster
        DEBIAN_TAG=buster-slim
        ghc_version=${GHC_VERSION}
        result_tag_debian=buster

        build_with_haskell
        ;;

    *)
        cat <<EOF
Unknown BOWLINE_BUILD_METHOD: $BOWLINE_BUILD_METHOD
EOF
        exit 1
        ;;
esac

exit 0


case "$1" in
    -h|--help)
        usage
        exit 0
        ;;

    '')       ## build with ghcup, default params
        set -x
        ghc_version=9.6.4
        GHC_VERSION=$ghc_version
        CABAL_VERSION=3.10.1.0
        DEBIAN_TAG=bookworm-slim
        result_tag_debian=bookworm

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
        result_tag_debian=${debian_rev}

        build_with_ghcup
        ;;

    haskell)  ## build with haskell docker image
        set -x
        image_tag="$2"

        case "$image_tag" in
            ''|9.4*-slim)
                HAKELL_TAG=9.4.8-slim-buster
                DEBIAN_TAG=buster-slim
                ghc_version=9.4.8
                result_tag_debian=buster

                build_with_haskell
                ;;
            9.6*-slim)
                HAKELL_TAG=9.6.4-slim-buster
                DEBIAN_TAG=buster-slim
                ghc_version=9.6.4
                result_tag_debian=buster
                ;;
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
$0 ghcup bookworm 9.6.4
$0 haskell 9.4-slim
$0 ghcup bookworm 9.4.8
$0 ghcup bullseye 9.6.4
$0 ghcup bullseye 9.4.8
$0 ghcup buster 9.4.8

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
