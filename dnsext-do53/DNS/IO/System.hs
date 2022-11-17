{-# LANGUAGE CPP #-}

module DNS.IO.System (
      getDefaultDnsServers
    ) where

import DNS.IO.Imports

#if !defined(mingw32_HOST_OS)
#define POSIX
#else
#define WIN
#endif

#if defined(WIN)
import Foreign.C.String
import Foreign.Marshal.Alloc (allocaBytes)
#else
import Data.Char (isSpace)
#endif

getDefaultDnsServers :: FilePath -> IO [String]

#if defined(WIN)

foreign import ccall "getWindowsDefDnsServers" getWindowsDefDnsServers :: CString -> Int -> IO Word32

getDefaultDnsServers _ = do
  allocaBytes 256 $ \cString -> do
     res <- getWindowsDefDnsServers cString 256
     case res of
       0 -> split ',' <$> peekCString cString
       _ -> return [] -- TODO: Do proper error handling here.
  where
    split :: Char -> String -> [String]
    split c cs =
        let (h, t) = dropWhile (== c) <$> break (== c) cs
         in if null t
            then if null h then [] else [h]
            else if null h
            then split c t
            else h : split c t

#else

getDefaultDnsServers file = toAddresses <$> readFile file
  where
    toAddresses :: String -> [String]
    toAddresses cs = map extract (filter ("nameserver" `isPrefixOf`) (lines cs))
    extract = reverse . dropWhile isSpace . reverse . dropWhile isSpace . drop 11

#endif
