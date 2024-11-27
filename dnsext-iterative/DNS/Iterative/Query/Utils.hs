{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module DNS.Iterative.Query.Utils where

-- GHC packages
import Data.List.NonEmpty (toList)

-- other packages

-- dnsext packages
import qualified DNS.Log as Log
import DNS.Types (DNSError (..), DNSMessage (..))
import qualified DNS.Types as DNS
import Data.IP (IP (IPv4, IPv6))
import System.Console.ANSI.Types

-- this package
import DNS.Iterative.Imports
import DNS.Iterative.Query.Types

clogLines :: (MonadIO m, MonadReader Env m) => Log.Level -> Maybe Color -> [String] -> m ()
clogLines level color xs = do
    putLines <- asks logLines_
    liftIO $ putLines level color xs

logLines :: (MonadIO m, MonadReader Env m) => Log.Level -> [String] -> m ()
logLines level xs = clogLines level Nothing xs

logLn :: (MonadIO m, MonadReader Env m) => Log.Level -> String -> m ()
logLn level s = clogLines level Nothing [s]

clogLn :: (MonadIO m, MonadReader Env m) => Log.Level -> Maybe Color -> String -> m ()
clogLn level color s = clogLines level color [s]

indent :: String -> String
indent = (replicate 4 ' ' ++)

{- FOURMOLU_DISABLE -}
pindents :: String -> [String] -> [String]
pindents _prefix  []     = []
pindents  prefix (x:xs)  = (prefix ++ ": " ++ x) : map indent xs
{- FOURMOLU_ENABLE -}

pprAddr :: Address -> String
pprAddr (ip, port) = show ip ++ "#" ++ show port

{- FOURMOLU_DISABLE -}
logQueryErrors :: String -> DNSQuery a -> DNSQuery a
logQueryErrors prefix q = do
      handleQueryError left return q
    where
      left qe = do
          logQueryError qe
          throwError qe
      logQueryError qe = case qe of
          DnsError de ss        -> logDnsError de ss
          NotResponse addrs resp msg  -> logNotResponse addrs resp msg
          InvalidEDNS addrs eh msg    -> logInvalidEDNS addrs eh msg
          HasError addrs rcode msg    -> logHasError addrs rcode msg
      logDnsError de ss = case de of
          NetworkFailure {}   -> putLog detail
          DecodeError {}      -> putLog detail
          RetryLimitExceeded  -> putLog detail
          UnknownDNSError {}  -> putLog detail
          _                   -> pure ()
        where detail = show de ++ ": " ++ intercalate ", " ss
      logNotResponse  addrs False  msg  = putLog $ pprAddrs addrs ++ ":\n" ++ pprMessage "not response:" msg
      logNotResponse _addrs True  _msg  = pure ()
      logInvalidEDNS  addrs DNS.InvalidEDNS  msg = putLog $ pprAddrs addrs ++ ":\n" ++ pprMessage "invalid EDNS:" msg
      logInvalidEDNS  _     _               _msg = pure ()
      logHasError _addrs _rcode _msg = pure ()
      pprAddrs = unwords . map show
      putLog = logLn Log.WARN . (prefix ++)
{- FOURMOLU_ENABLE -}

printResult :: Either QueryError DNSMessage -> IO ()
printResult = either print (putStr . pprMessage "result")

{- FOURMOLU_DISABLE -}
pprMessage :: String -> DNSMessage -> String
pprMessage title DNSMessage{..} =
    unlines $ (title ++ ":") : map ("  " ++)
    ( [ "identifier: " ++ show identifier
      , "opcode: " ++ show opcode
      , "rcode: " ++ show rcode
      , "flags: " ++ show flags
      , "edns-header: " ++ show ednsHeader
      ]
      ++
      [ "question:" ]
      ++
      map (("  " ++) . show) question
      ++
      [ "answer:" ]
      ++
      map (("  " ++) . show) answer
      ++
      [ "authority:" ]
      ++
      map (("  " ++) . show) authority
      ++
      [ "additional:" ]
      ++
      map (("  " ++) . show) additional
    )
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
ppDelegation :: Bool -> NonEmpty DEntry -> String
ppDelegation short des
    | short      = ppShort
    | otherwise  = ppFull
  where
    ppFull  = intercalate "\n" [indent s | s <- names]
    ppShort = intercalate "\n" [indent s | s <- nsHd ++ suffix]
    suffix = [ "... " ++ note  ++ " ..." | not $ null glTl ]
    note = "plus " ++ show (length glTl) ++ " names and " ++ show (sum glTl) ++ " glues"
    nsHd = take n names
    glTl = drop n glues
    n = 2
    (names, glues) = unzip $ ppDelegations des
{- FOURMOLU_ENABLE -}

ppDelegations :: NonEmpty DEntry -> [(String, Int)]
ppDelegations des =
    map (pp . bundle) $ groupBy ((==) `on` fst) $ map toT $ toList des
  where
    withP toIP is p = [(toIP i, p) | i <- toList is]
    toT (DEwithAx d i4s i6s) = (d, withP IPv4 i4s 53 ++ withP IPv6 i6s 53)
    toT (DEwithA4 d i4s) = (d, withP IPv4 i4s 53)
    toT (DEwithA6 d i6s) = (d, withP IPv6 i6s 53)
    toT (DEonlyNS d) = (d, [])
    toT (DEstubA4 i4s) = ("<stub>", [(IPv4 i, p) | (i, p) <- toList i4s])
    toT (DEstubA6 i6s) = ("<stub>", [(IPv6 i, p) | (i, p) <- toList i6s])
    bundle xss@(x : _) = (fst x, concatMap snd xss)
    bundle [] = ("", []) -- never reach
    pp (d, is) = (show d ++ " " ++ unwords (map pprAddr is), length is)
