{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import qualified Control.Exception as E
import Control.Monad
import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.DoX.Client
import DNS.SEC
import DNS.SVCB
import DNS.Types
import DNS.Types.Decode
import DNS.Types.Encode
import Data.ByteString (ByteString)
import Data.IP ()
import qualified Data.List.NonEmpty as NE
import Network.Socket
import qualified Network.Socket.ByteString as NSB
import System.Environment

-- fixme: saving resumption info

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
        [] -> putStrLn "ddrd ipaddr [ipaddr...]"
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
        bssa <- NSB.recvFrom s 2048
        piplineResolver <- selectSVCB <$> lookupSVCBInfo env
        piplineResolver (serverLoop s bssa) `E.catch` \(E.SomeException se) -> print se
        loop

serverLoop :: Socket -> (ByteString, SockAddr) -> (Question -> QueryControls -> IO (Either DNSError Reply)) -> IO ()
serverLoop s (bs0, sa0) resolver = do
    sendReply bs0 sa0
    loop
  where
    loop = do
        (bs, sa) <- NSB.recvFrom s 2048
        sendReply bs sa
        loop
    sendReply bs sa =
        case decode bs of
            Left _ -> error "serverLoop (1)"
            Right msg -> case question msg of
                [] -> return ()
                q : _ -> do
                    let idnt = identifier msg
                    eres <- resolver q mempty
                    case eres of
                        Left _ -> error "serverLoop (2)"
                        Right res -> do
                            let msg' =
                                    (replyDNSMessage res)
                                        { identifier = idnt
                                        }
                            void $ NSB.sendTo s (encode msg') sa

selectSVCB :: Either DNSError [[SVCBInfo]] -> PipelineResolver
selectSVCB (Left _) = error "selectSVCB Left"
selectSVCB (Right []) = error "selectSVCB Right"
selectSVCB (Right (sis : _)) = case toPipelineResolvers $ map modifyForDDR sis of
    [] -> error "selectSVCB"
    ps : _ -> case ps of
        [] -> error "selectSVCB"
        p : _ -> p

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
