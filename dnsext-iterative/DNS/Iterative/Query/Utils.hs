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

logLines :: Log.Level -> [String] -> ContextT IO ()
logLines level xs = do
    putLines <- asks logLines_
    liftIO $ putLines level Nothing xs

logLn :: Log.Level -> String -> ContextT IO ()
logLn level = logLines level . (: [])

clogLn :: Log.Level -> Maybe Color -> String -> ContextT IO ()
clogLn level color s = do
    putLines <- asks logLines_
    liftIO $ putLines level color [s]

{- FOURMOLU_DISABLE -}
logQueryErrors :: String -> DNSQuery a -> DNSQuery a
logQueryErrors prefix q = do
      handleDnsError left return q
    where
      left qe = do
          lift $ logQueryError qe
          throwE qe
      logQueryError qe = case qe of
          DnsError de           -> logDnsError de
          NotResponse resp msg  -> logNotResponse resp msg
          InvalidEDNS eh msg    -> logInvalidEDNS eh msg
          HasError rcode msg    -> logHasError rcode msg
          QueryDenied           -> logQueryDenied
      logDnsError de = case de of
          NetworkFailure {}   -> putLog $ show de
          DecodeError {}      -> putLog $ show de
          UnknownDNSError {}  -> putLog $ show de
          _                   -> pure ()
      logNotResponse False  msg  = putLog $ pprMessage "not response:" msg
      logNotResponse True  _msg  = pure ()
      logInvalidEDNS DNS.InvalidEDNS  msg = putLog $ pprMessage "invalid EDNS:" msg
      logInvalidEDNS _               _msg = pure ()
      logHasError _rcode _msg = pure ()
      logQueryDenied = pure ()
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
data PPMode
    = PPShort
    | PPFull
    deriving Show

putDelegation :: Applicative f => PPMode -> NonEmpty DEntry -> (String -> f ()) -> (String -> f ()) -> f ()
putDelegation pprs des h fallback  = case pprs of
    PPFull   -> h ppFull
    PPShort  -> h ppShort *> unless (null suffix) (fallback ppFull)
  where
    ppFull  = "\t" ++ intercalate "\n\t" (map fst pps)
    ppShort = "\t" ++ intercalate "\n\t" (map fst hd ++ suffix)
    suffix = [ "... " ++ note  ++ " ..." | not $ null tl ]
    note = "plus " ++ show (length tl) ++ " names and " ++ show (sum $ map snd tl) ++ " glues"
    (hd, tl) = splitAt 2 pps
    pps = ppDelegations des
{- FOURMOLU_ENABLE -}

ppDelegation :: NonEmpty DEntry -> String
ppDelegation des = "\t" ++ intercalate "\n\t" (map fst $ ppDelegations des)

ppDelegations :: NonEmpty DEntry -> [(String, Int)]
ppDelegations des =
    map (pp . bundle) $ groupBy ((==) `on` fst) $ map toT $ toList des
  where
    toT (DEwithAx d i4s i6s) = (d, map IPv4 (toList i4s) ++ map IPv6 (toList i6s))
    toT (DEwithA4 d i4s) = (d, map IPv4 $ toList i4s)
    toT (DEwithA6 d i6s) = (d, map IPv6 $ toList i6s)
    toT (DEonlyNS d) = (d, [])
    bundle xss@(x : _) = (fst x, concatMap snd xss)
    bundle [] = ("", []) -- never reach
    pp (d, is) = (show d ++ " " ++ show is, length is)
