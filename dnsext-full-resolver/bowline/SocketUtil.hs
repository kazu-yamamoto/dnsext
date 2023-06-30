module SocketUtil (
    addrInfo,
    mkSocketWaitForByte,
    isAnySockAddr,
) where

-- GHC internal packages
import GHC.IO.Device (IODevice (ready))
import GHC.IO.FD (mkFD)

-- GHC packages
import System.IO (IOMode (ReadMode))

-- dns packages
import Network.Socket (
    AddrInfo (..),
    HostName,
    PortNumber,
    SockAddr (..),
    Socket,
 )
import qualified Network.Socket as S

addrInfo :: PortNumber -> [HostName] -> IO [AddrInfo]
addrInfo p [] = S.getAddrInfo Nothing Nothing $ Just $ show p
addrInfo p hs@(_ : _) =
    concat <$> sequence [S.getAddrInfo Nothing (Just h) $ Just $ show p | h <- hs]

{- make action to wait for socket-input from cached FD
   without calling fdStat and mkFD for every wait-for calls -}
mkSocketWaitForByte :: Socket -> IO (Int -> IO Bool)
mkSocketWaitForByte sock =
    withFD <$> S.withFdSocket sock getFD
  where
    withFD fd millisec =
        ready fd False millisec
    getFD fd =
        fst
            <$> mkFD
                fd
                ReadMode
                Nothing {- stat, filled in `mkFD`, calling `fdStat` -}
                False {- socket flag for only Windows -}
                False {- non-blocking, False -}
                {-
                mkSocketWaitForInput sock =
                  withStat <$> withFdSocket sock fdStat
                  where
                    withStat stat millisec = do
                      (fd, _) <- withFdSocket sock $ getFD stat
                      ready fd False millisec
                    getFD stat fd =
                      mkFD fd ReadMode
                      (Just stat)  {- stat, get from `fdStat` -}
                      False        {- socket flag for only Windows -}
                      False        {- non-blocking, False -}

                -- import System.Posix.Internals (fdStat)
                -}

isAnySockAddr :: SockAddr -> Bool
isAnySockAddr (SockAddrInet _ 0) = True
isAnySockAddr (SockAddrInet6 _ _ (0, 0, 0, 0) _) = True
isAnySockAddr _ = False
