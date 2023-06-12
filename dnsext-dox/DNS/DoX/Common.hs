{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.Common where

import DNS.Do53.Internal (Recv)
import DNS.DoX.Imports
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Default.Class (def)
import Network.HTTP.Types
import Network.QUIC.Client
import Network.QUIC.Internal hiding (Recv, shared)
import Network.Socket
import Network.TLS hiding (HostName)
import Network.TLS.Extra
import System.IO.Error (isEOFError)
import qualified UnliftIO.Exception as E

----------------------------------------------------------------

type WireFormat = ByteString

type ALPN = ByteString

----------------------------------------------------------------

clientDoHHeaders :: WireFormat -> RequestHeaders
clientDoHHeaders bs =
    [ (hUserAgent, "HaskellQuic/0.0.0")
    , (hContentType, "application/dns-message")
    , (hAccept, "application/dns-message")
    , (hContentLength, C8.pack $ show len)
    ]
  where
    len = C8.length bs

----------------------------------------------------------------

makeAddrInfo :: HostName -> PortNumber -> IO AddrInfo
makeAddrInfo addr port = do
    let flgs = [AI_ADDRCONFIG, AI_NUMERICSERV, AI_PASSIVE]
        hints =
            defaultHints
                { addrFlags = flgs
                , addrSocketType = Stream
                }
        port' = show port
    head <$> getAddrInfo (Just hints) (Just addr) (Just port')

----------------------------------------------------------------

getTLSParams :: HostName -> ALPN -> Bool -> ClientParams
getTLSParams serverName alpn validate =
    (defaultParamsClient serverName "")
        { clientSupported = supported
        , clientWantSessionResume = Nothing
        , clientUseServerNameIndication = True
        , clientShared = shared
        , clientHooks = hooks
        }
  where
    shared =
        def
            { sharedValidationCache = validateCache
            }
    supported =
        def -- TLS.Supported
            { supportedVersions = [TLS13, TLS12]
            , supportedCiphers = ciphersuite_strong
            , supportedCompressions = [nullCompression]
            , supportedSecureRenegotiation = True
            , supportedClientInitiatedRenegotiation = False
            , supportedSession = True
            , supportedFallbackScsv = True
            , supportedGroups = [X25519, P256, P384]
            }
    hooks =
        def
            { onSuggestALPN = return $ Just [alpn]
            }
    validateCache
        | validate = def
        | otherwise =
            ValidationCache
                (\_ _ _ -> return ValidationCachePass)
                (\_ _ _ -> return ())

----------------------------------------------------------------

sendTLS :: Context -> WireFormat -> IO ()
sendTLS ctx = sendData ctx . LBS.fromStrict

sendManyTLS :: Context -> [WireFormat] -> IO ()
sendManyTLS ctx = sendData ctx . LBS.fromChunks

-- TLS version of recv (decrypting) without a cache.
recvTLS :: Context -> Recv
recvTLS ctx = E.handle onEOF $ recvData ctx
  where
    onEOF e
        | Just Error_EOF <- E.fromException e = return ""
        | Just ioe <- E.fromException e, isEOFError ioe = return ""
        | otherwise = E.throwIO e

----------------------------------------------------------------

getQUICParams :: HostName -> PortNumber -> ALPN -> ClientConfig
getQUICParams hostname port alpn =
    defaultClientConfig
        { ccServerName = hostname
        , ccPortName = show port
        , ccALPN = \_ -> return $ Just [alpn]
        , ccDebugLog = False
        , ccValidate = False
        , ccVersions = [Version1]
        }
