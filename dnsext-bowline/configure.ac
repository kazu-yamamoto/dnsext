AC_INIT([Haskell bowline package],
        [0.0.0],
        [],
        [bowline])

AC_CONFIG_SRCDIR([include/HsSockOpt.h])

AC_CONFIG_HEADERS([include/HsSockOptConfig.h])

AC_CANONICAL_HOST

AC_CHECK_HEADERS([netinet/in.h netinet/tcp.h])

AC_CHECK_DECLS([IPPROTO_TCP], [], [],
[AC_INCLUDES_DEFAULT[
#ifdef HAVE_NETINET_TCP_H
# include <netinet/in.h>
#endif
]])

AC_OUTPUT
