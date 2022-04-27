module DNSC.SocketUtil (
  mkSocketWaitForInput,
  isAnySockAddr,
  ) where

-- GHC internal packages
import GHC.IO.Device (IODevice (ready))
import GHC.IO.FD (mkFD)

-- GHC packages
import System.IO (IOMode (ReadMode))

-- dns packages
import Network.Socket (Socket, withFdSocket, SockAddr (..))


{- make action to wait for socket-input from cached FD
   without calling fdStat and mkFD for every wait-for calls -}
mkSocketWaitForInput :: Socket -> IO (Int -> IO Bool)
mkSocketWaitForInput sock =
  withFD <$> withFdSocket sock getFD
  where
    withFD fd millisec =
      ready fd False millisec
    getFD fd =
      fst <$>
      mkFD fd ReadMode
      Nothing      {- stat, filled in `mkFD`, calling `fdStat` -}
      False        {- socket flag for only Windows -}
      False        {- non-blocking, False -}
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
isAnySockAddr (SockAddrInet _ 0)              = True
isAnySockAddr (SockAddrInet6 _ _ (0,0,0,0) _) = True
isAnySockAddr _                               = False
