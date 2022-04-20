module DNSC.SocketUtil (
  mkSocketWaitForInput,
  ) where

import GHC.IO.Device (IODevice (ready))
import GHC.IO.FD (mkFD)

import System.IO (IOMode (ReadMode))

import Network.Socket (Socket, withFdSocket)


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
