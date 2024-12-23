{-# LANGUAGE PatternSynonyms #-}
module SockOpt where

import Network.Socket (SocketOption (..))

#include <HsSockOpt.h>

-- | TCP_KEEPIDLE
pattern TcpKeepIdle :: SocketOption
#ifdef TCP_KEEPIDLE
pattern TcpKeepIdle       = SockOpt (#const IPPROTO_TCP) (#const TCP_KEEPIDLE)
#else
pattern TcpKeepIdle       = SockOpt (-1) (-1)
#endif

-- | TCP_KEEPINTVL
pattern TcpKeepInterval :: SocketOption
#ifdef TCP_KEEPINTVL
pattern TcpKeepInterval   = SockOpt (#const IPPROTO_TCP) (#const TCP_KEEPINTVL)
#else
pattern TcpKeepInterval   = SockOpt (-1) (-1)
#endif
