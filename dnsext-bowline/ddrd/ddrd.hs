{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Concurrent
import qualified Control.Exception as E
import Control.Monad
import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Client
import DNS.DoX.Internal
import DNS.SEC
import DNS.SVCB
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode
import Data.IP ()
import qualified Data.List.NonEmpty as NE
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import System.Environment

serverAddr :: String
serverAddr = "127.0.0.1"

serverPort :: String
serverPort = "53"

serverResolve :: HostName -> ServiceName -> IO AddrInfo
serverResolve addr port = NE.head <$> getAddrInfo (Just hints) (Just addr) (Just port)
  where
    hints =
        defaultHints
            { addrFlags = [AI_NUMERICHOST, AI_NUMERICSERV, AI_PASSIVE]
            , addrSocketType = Datagram
            }

serverSocket :: AddrInfo -> IO Socket
serverSocket ai = E.bracketOnError (openSocket ai) close $ \s -> do
    setSocketOption s ReuseAddr 1
    bind s $ addrAddress ai
    return s

main :: IO ()
main = do
    args <- getArgs
    case args of
        [] -> error "usage"
        addrs -> do
            runInitIO $ do
                addResourceDataForDNSSEC
                addResourceDataForSVCB
            ai <- serverResolve serverAddr serverPort
            E.bracket (serverSocket ai) close $ \s -> do
                let conf = makeConf addrs
                withLookupConf conf $ mainLoop s

mainLoop :: Socket -> LookupEnv -> IO ()
mainLoop s env = loop
  where
    loop = do
        piplineResolver <- selectSVCB <$> lookupSVCBInfo env
        piplineResolver (serverLoop s) `E.catch` \(E.SomeException se) -> print se
        loop

serverLoop :: Socket -> Resolver -> IO ()
serverLoop s resolver = loop
  where
    loop = do
        (bs, sa) <- NSB.recvFrom s 2048
        case decode bs of
            Left _ -> error "serverLoop (1)"
            Right msg -> do
                let idnt = identifier msg
                eres <- resolver (head $ question msg) mempty
                case eres of
                    Left _ -> error "serverLoop (2)"
                    Right res -> do
                        let msg' =
                                (replyDNSMessage res)
                                    { identifier = idnt
                                    }
                        void $ NSB.sendTo s (encode msg') sa
        loop

selectSVCB :: Either DNSError [[SVCBInfo]] -> PipelineResolver
selectSVCB (Left _) = error "selectSVCB Left"
selectSVCB (Right []) = error "selectSVCB Right"
selectSVCB (Right (sis : _)) = head $ head $ toPipelineResolvers $ map modifyForDDR sis

makeConf :: [String] -> LookupConf
makeConf addrs =
    defaultLookupConf
        { lconfCacheConf = Just defaultCacheConf
        , lconfConcurrent = True
        , lconfSeeds = SeedsAddrs $ map read addrs
        , lconfActions =
            actions
                { ractionUseEarlyData = True
                , ractionValidate = False
                }
        }
  where
    actions = lconfActions defaultLookupConf
