{-# LANGUAGE RecordWildCards #-}

module Main where

import Data.List
import System.Exit
import System.Process

dug :: String
dug = "dist/build/dug/dug"

domains :: [String]
domains = ["www.mew.org", "www.jprs.jp"]

input :: String
input = ""

main :: IO ()
main = mapM_ testCompany profiles

data Profile = Profile
    { company :: String
    , serverName :: String
    , transports :: [String]
    , ipAddr :: String
    , transportsIP :: [String]
    , ipInCert :: Bool
    }

profiles :: [Profile]
profiles =
    [ Profile
        { company = "Google"
        , serverName = "dns.google"
        , transports = ["udp", "tcp", "dot", "h2", "auto"]
        , ipAddr = "8.8.8.8"
        , -- 8.8.8.8 + h3 is not allowed since SNI must be a hostname, sigh
          transportsIP = ["udp", "tcp", "dot", "h2", "auto"]
        , ipInCert = True
        }
    , Profile
        { company = "Cloudfare"
        , serverName = "one.one.one.one"
        , transports = ["udp", "tcp", "dot", "h2", "h3", "auto"]
        , ipAddr = "1.1.1.1"
        , transportsIP = ["udp", "tcp", "dot", "h2", "h3", "auto"]
        , ipInCert = True
        }
    , Profile
        { company = "AdGuard"
        , serverName = "unfiltered.adguard-dns.com"
        , transports = ["udp", "tcp", "dot", "doq", "h2", "h3", "auto"]
        , ipAddr = "94.140.14.140"
        , transportsIP = ["udp", "tcp", "dot", "doq", "h2", "h3", "auto"]
        , ipInCert = True
        }
    , Profile
        { company = "IIJ"
        , serverName = "public.dns.iij.jp"
        , transports = ["dot", "h2"]
        , ipAddr = "103.2.57.5"
        , transportsIP = ["dot", "h2"]
        , ipInCert = False -- No IP addresses in certificate
        }
    ]

testCompany :: Profile -> IO ()
testCompany Profile{..} = do
    putStrLn $ company ++ "..."
    mapM_ (runTest serverName True) transports
    mapM_ (runTest ipAddr ipInCert) transportsIP
    putStrLn $ company ++ "...done"

runTest :: String -> Bool -> String -> IO ()
runTest host certCheck transport = do
    -- AdGuard is using certificates signed by ZeroSSL.
    -- This means that IPv6 addresses are not contained in SAN, sign.
    let workaround
            | host == "unfiltered.adguard-dns.com" = ["-4"]
            | otherwise = []
        options
            | certCheck = ["-e"] ++ workaround
            | otherwise = []
    let args = ['@' : host] ++ options ++ ["-d", transport] ++ domains
    (ec, out, err) <- readProcessWithExitCode dug args input
    case ec of
        ExitSuccess -> return ()
        ExitFailure _ -> do
            putStrLn "FAILED FAILED FAILED FAILED FAILED FAILED"
            putStrLn $ "    " ++ dug ++ " " ++ intercalate " " args
            putStrLn "stdout:"
            putStrLn out
            putStrLn "stderr:"
            putStrLn err
            exitFailure
