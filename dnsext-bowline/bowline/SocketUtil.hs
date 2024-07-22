module SocketUtil (
    ainfosSkipError,
    foldAddrInfo,
) where

-- GHC packages
import Data.Functor
import Data.List
import Data.Maybe
import Text.Read (readMaybe)
import System.IO.Error (tryIOError)

-- dns packages
import Data.IP (IP)
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
-- expected behavior examples in a typical environments
--
--   53 []                      -->  0.0.0.0:53, [::]:53
--   53 ["0.0.0.0", "::"]       -->  0.0.0.0:53, [::]:53
--   53 ["localhost"]           -->  127.0.0.1:53, [::1]:53
--   53 ["127.0.0.1", "::1"]    -->  127.0.0.1:53, [::1]:53
ainfosSkipError :: (String -> IO ()) -> SocketType -> PortNumber -> [HostName] -> IO [AddrInfo]
ainfosSkipError logLn sty p hs = case hs of
    []   -> foldAddrInfo' sty Nothing p
    _:_  -> concat <$> sequence [ainfoSkip h p | h <- hs]
  where
    ainfoSkip host port = case (readMaybe host :: Maybe IP) of
        Nothing  ->            foldAddrInfo' sty (Just host) port
        Just {}  -> take 1 <$> foldAddrInfo' sty (Just host) port  {- assume the first is the best -}
    foldAddrInfo' = foldAddrInfo left pure
    left e = logLn (estring $ show e) $> []
    estring s = "skipping : " ++ fromMaybe s (stripPrefix "Network.Socket." s)
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
_checks :: IO ()
_checks =
    mapM_ check
    [[], ["0.0.0.0", "::"], ["localhost"], ["127.0.0.1", "::1"]]
  where
    check ns =  do
        as <- ainfosSkipError putStrLn S.Datagram 53 ns
        putStr $ unlines $
            (show ns ++ ":") : map (("  " ++) . show) as
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
    right1 as = right [ai | ai <- as, addrSocketType ai == socktype]
{- FOURMOLU_ENABLE -}
