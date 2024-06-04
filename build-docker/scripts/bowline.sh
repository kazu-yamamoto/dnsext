#! /bin/sh

case "$1" in
	sh|bash)
		exe="$1"
		shift
		exec /bin/$exe "$@"
		;;
	dug)
		shift
		exec /opt/bowline/bin/dug "$@"
		;;
	*)
		exec /opt/bowline/bin/bowline /opt/bowline/etc/bowline.conf "$@"
		;;
esac
