module SocketUtil (
    ainfosSkipError,
    foldAddrInfo,
) where

-- GHC packages
import Data.Functor
import Data.List
import Data.Maybe
import System.IO.Error (tryIOError)

-- dns packages
import Network.Socket (
    AddrInfo (..),
    AddrInfoFlag (..),
    HostName,
    PortNumber,
    SocketType (..),
    defaultHints,
 )
import qualified Network.Socket as S

{- FOURMOLU_DISABLE -}
ainfosSkipError :: (String -> IO ()) -> SocketType -> PortNumber -> [HostName] -> IO [AddrInfo]
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
foldAddrInfo :: (IOError -> IO a) -> ([AddrInfo] -> IO a) -> SocketType -> Maybe HostName -> PortNumber -> IO a
foldAddrInfo left right socktype mhost port =
    either left right1 =<< tryIOError (S.getAddrInfo (Just hints) mhost (Just $ show port))
  where
    hints = defaultHints {
                  addrFlags = [AI_PASSIVE]
                , addrSocketType = socktype
                }
    right1 as = right . catMaybes =<< mapM inet as
    inet ai
        | addrSocketType ai == socktype  = pure $ Just ai
        | otherwise                      = pure Nothing
{- FOURMOLU_ENABLE -}
