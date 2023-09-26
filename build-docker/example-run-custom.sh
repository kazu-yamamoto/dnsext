#! /bin/sh

usage() {
    cat <<EOF
Usage: $0

       $0 {-N | CUSTOM_CONF_DIR} {default|bookworm|bullseye|buster}

       $0 {-N | CUSTOM_CONF_DIR} IMAGE

       $0 {-h|--help}
EOF
}

with_volume() {
    image="$1"
    conf_dir="$2"

    name=bowline-custom
    docker container stop ${name} || true
    docker container rm ${name} || true
    docker volume rm bowline-conf

    docker volume create bowline-conf
    docker container create \
           -ti \
           --name ${name} \
           --mount type=volume,src=bowline-conf,dst=/opt/bowline/etc/ \
           ${image}
    for fn in ${conf_dir}/* ; do
        docker cp ${fn} ${name}:/opt/bowline/etc/
    done

    docker container start -ai ${name}
}

set -e

case "$2" in
    ''|bookworm)
        image=bowline:bookworm
        ;;
    bullseye)
        image=bowline:bullseye
        ;;
    buster)
        image=bowline:buster
        ;;
    *)
        image="$2"
        ;;
esac

case "$1" in
    -h|--help)
        usage
        exit 0
        ;;

    -N)
        set -x
        docker container rm bowline-default || true
        docker run -ti --name bowline-default ${image}
        exit 0
        ;;

    '')
        conf_dir=custom-conf
        ;;

    *)
        conf_dir="$1"
        ;;
esac

if [ ! -d $conf_dir ]; then
    cat <<EOF
Directory not found: $conf_dir
EOF
    usage
    exit 1
fi

set -x
with_volume $image $conf_dir
