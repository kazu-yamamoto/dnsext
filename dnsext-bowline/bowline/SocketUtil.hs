module SocketUtil (
    addrInfo,
    ainfosSkipError,
    foldAddrInfo,
    mkSocketWaitForByte,
    isAnySockAddr,
) where

-- GHC internal packages
import GHC.IO.Device (IODevice (ready))
import GHC.IO.FD (mkFD)
import Data.Functor
import Data.List
import Data.Maybe

-- GHC packages
import System.IO (IOMode (ReadMode))
import System.IO.Error (tryIOError)

-- dns packages
import Network.Socket (
    AddrInfo (..),
    HostName,
    NameInfoFlag (..),
    PortNumber,
    ServiceName,
    SockAddr (..),
    Socket,
    SocketType (..),
 )
import qualified Network.Socket as S

addrInfo :: PortNumber -> [HostName] -> IO [AddrInfo]
addrInfo p [] = S.getAddrInfo Nothing Nothing $ Just $ show p
addrInfo p hs@(_ : _) =
    concat <$> sequence [S.getAddrInfo Nothing (Just h) $ Just $ show p | h <- hs]

{- FOURMOLU_DISABLE -}
ainfosSkipError :: (String -> IO ()) -> SocketType -> PortNumber -> [HostName] -> IO [(AddrInfo, HostName, ServiceName)]
ainfosSkipError logLn sty p hs = case hs of
    []   -> ainfoSkip sty Nothing p
    _:_  -> concat <$> sequence [ainfoSkip sty (Just h) p | h <- hs]
  where
    ainfoSkip = foldAddrInfo left right
    left e = logLn (estring $ show e) $> []
    estring s = "skipping : " ++ fromMaybe s (stripPrefix "Network.Socket." s)
    right = pure . take 1  {- assume the first is the best -}
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
foldAddrInfo :: (IOError -> IO a) -> ([(AddrInfo, HostName, ServiceName)] -> IO a) -> SocketType -> Maybe HostName -> PortNumber -> IO a
foldAddrInfo left right socktype mhost port =
    either left right1 =<< tryIOError (S.getAddrInfo Nothing mhost $ Just $ show port)
  where
    right1 as = right . catMaybes =<< mapM inet as
    inet ai
        | addrSocketType ai == socktype  = ainfoInetAddr ai
        | otherwise                      = pure Nothing
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
ainfoInetAddr :: AddrInfo -> IO (Maybe (AddrInfo, HostName, ServiceName))
ainfoInetAddr ai = do
    (mhost, mport) <- S.getNameInfo [NI_NUMERICHOST, NI_NUMERICSERV] True True $ addrAddress ai
    pure $ do host <- mhost
              port <- mport
              Just (ai, host, port)
{- FOURMOLU_ENABLE -}

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
