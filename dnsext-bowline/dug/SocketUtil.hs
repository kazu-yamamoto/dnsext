module SocketUtil where

import Control.Exception (bracket)
import Data.Functor
import Data.IP (IP (..))
import Network.Socket (AddrInfo (..), AddrInfoFlag (..), SocketType (..))
import qualified Network.Socket as S
import System.IO.Error (tryIOError)

{- FOURMOLU_DISABLE -}
checkDisableV6 :: [IP] -> IO Bool
checkDisableV6 addrs
    | v6:_ <- v6s  = either (disabled . show) pure =<< tryIOError (checkV6 v6)
    | otherwise    = pure False
  where
    v6s = [v6 | IPv6 v6 <- addrs]
    {- Check whether IPv6 is available by specifying `AI_ADDRCONFIG` to `addrFlags` of hints passed to `getAddrInfo`.
       If `Nothing` is passed to `hints`, the default value of `addrFlags` is implementation-dependent.
       * Glibc: `[AI_ADDRCONFIG, AI_V4MAPPED]`.
           * https://man7.org/linux/man-pages/man3/getaddrinfo.3.html#DESCRIPTION
       * POSIX, BSD: `[]`.
           * https://man.freebsd.org/cgi/man.cgi?query=getaddrinfo&sektion=3
       So, specifying `AI_ADDRCONFIG` explicitly. -}
    datagramAI6 an srv = S.getAddrInfo (Just S.defaultHints{addrFlags = [AI_ADDRCONFIG], addrSocketType = Datagram}) (Just an) srv
    disabled e = putStrLn ("disabling IPv6: " ++ e) $> True
    checkRoute (sa:_) (AddrInfo{addrAddress = peer}:_)  = (bracket (S.openSocket sa) S.close $ \s -> S.connect s peer) $> False
    checkRoute  _      _                                = disabled "cannot get IPv6 address"
    checkV6 dst  = do
        local   <- datagramAI6  "::"      Nothing
        remote  <- datagramAI6 (show dst) Nothing
        checkRoute local remote
{- FOURMOLU_ENABLE -}
