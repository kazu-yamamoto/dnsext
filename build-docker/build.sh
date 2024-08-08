#! /bin/sh

usage() {
        cat <<EOF
Usage: $0 -n [REVISION_TO_BUILD [CLONE_URL]]

         Not execute, but print commands

       $0 -x [REVISION_TO_BUILD [CLONE_URL]]

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
    tag_bowline=bowline:${bowline_revision}
    $N docker buildx build \
           -t ${tag_bowline} \
           --build-arg GHC_OPTIMIZE=${GHC_OPTIMIZE} \
           --build-arg GHC_PARALLEL=${GHC_PARALLEL} \
           --build-arg CABAL_PARALLEL=${CABAL_PARALLEL} \
           \
           --build-arg GHC_VERSION=${GHC_VERSION} \
           --build-arg CABAL_VERSION=${CABAL_VERSION} \
           --build-arg BUILDER_IMAGE=${BUILDER_IMAGE} \
           --build-arg DEBIAN_TAG=${DEBIAN_TAG} \
           --build-arg PRIVKEY_ALG=${PRIVKEY_ALG} \
           --build-arg PRIVKEY_ALGOPT=${PRIVKEY_ALGOPT} \
           --build-arg CHAIN_SUBJ_CN=${CHAIN_SUBJ_CN} \
           --build-arg CLONE_URL=${CLONE_URL} \
           --build-arg DNSEXT_REV=${DNSEXT_REV} \
           -f Dockerfile.ghcup \
           .

    tag_ghcup=bowline:${ghc_version}-${result_tag_debian}-ghcup
    $N docker image tag ${tag_bowline} ${tag_ghcup}
    if [ "${ghc_version}" = 9.6.4 ]; then
        $N docker image tag ${tag_ghcup} bowline:${result_tag_debian}
        if [ "${result_tag_debian}" = bookworm ]; then
            $N docker image tag bowline:${result_tag_debian} bowline:latest
        fi
    fi
}

build_with_haskell() {
    $N docker buildx build \
           -t bowline:${ghc_version}-${result_tag_debian}-haskell \
           --build-arg GHC_OPTIMIZE=${GHC_OPTIMIZE} \
           --build-arg GHC_PARALLEL=${GHC_PARALLEL} \
           --build-arg CABAL_PARALLEL=${CABAL_PARALLEL} \
           \
           --build-arg HAKELL_TAG=${HAKELL_TAG} \
           --build-arg BUILDER_IMAGE=${BUILDER_IMAGE} \
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

N=:
case "$1" in
    -h|--help)
        usage
        exit 0
        ;;

    -n)
        ;;

    -x)
        N=''
        ;;

    *)
        usage
        exit 1
        ;;
esac
shift

set -x
DNSEXT_REV="$1"
[ x"$DNSEXT_REV" != x ] || DNSEXT_REV=dist-latest

CLONE_URL="$2"
[ x"$CLONE_URL" != x ] || CLONE_URL=http://github.com/kazu-yamamoto/dnsext

bowline_revision=${DNSEXT_REV#dist-}
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
        BUILDER_IMAGE=debian:${DEBIAN_TAG}
        result_tag_debian=${debian_rev}

        build_with_ghcup
        ;;

    haskell)
        [ x"$GHC_VERSION" != x ] || GHC_VERSION=9.4.8
        #--
        set -x
        HAKELL_TAG=${GHC_VERSION}-slim-buster
        BUILDER_IMAGE=haskell:${GHC_VERSION}-slim-buster
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
