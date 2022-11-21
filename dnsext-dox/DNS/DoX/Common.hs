{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.Common where

import DNS.Do53.Client
import DNS.Types
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Default.Class (def)
import Network.HTTP.Types
import Network.QUIC.Client
import Network.QUIC.Internal hiding (Recv)
import Network.Socket
import Network.Socket.BufferPool
import Network.TLS hiding (HostName)
import Network.TLS.Extra
import System.IO.Error (isEOFError)
import qualified UnliftIO.Exception as E

----------------------------------------------------------------

type WireFormat = ByteString

----------------------------------------------------------------

iijQ :: Question
iijQ = Question "www.iij.ad.jp" A classIN

iij :: ByteString
iij = encodeQuery 100 iijQ mempty

mewQ :: Question
mewQ = Question "www.mew.org" A classIN

mew :: ByteString
mew = encodeQuery 100 mewQ mempty

----------------------------------------------------------------

clientDoHHeaders :: RequestHeaders
clientDoHHeaders = [
    (hUserAgent,   "HaskellQuic/0.0.0")
  , (hContentType, "application/dns-message")
  , (hAccept,      "application/dns-message")
  ]

----------------------------------------------------------------

makeAddrInfo :: Maybe HostName -> PortNumber -> IO AddrInfo
makeAddrInfo maddr port = do
    let flgs = [AI_ADDRCONFIG, AI_NUMERICSERV, AI_PASSIVE]
        hints = defaultHints {
            addrFlags = flgs
          , addrSocketType = Stream
          }
    head <$> getAddrInfo (Just hints) maddr (Just $ show port)

----------------------------------------------------------------

getTLSParams :: HostName -> ByteString -> Bool -> ClientParams
getTLSParams serverName alpn validate
    = (defaultParamsClient serverName "") {
    clientSupported = supported
  , clientWantSessionResume = Nothing
  , clientUseServerNameIndication = True
  , clientShared = shared
  , clientHooks = hooks
  }
  where
    shared = def {
        sharedValidationCache = validateCache
      }
    supported = def { -- TLS.Supported
        supportedVersions       = [TLS13,TLS12]
      , supportedCiphers        = ciphersuite_strong
      , supportedCompressions   = [nullCompression]
      , supportedSecureRenegotiation = True
      , supportedClientInitiatedRenegotiation = False
      , supportedSession             = True
      , supportedFallbackScsv        = True
      , supportedGroups              = [X25519,P256,P384]
      }
    hooks = def {
        onSuggestALPN = return $ Just [alpn]
      }
    validateCache
      | validate = def
      | otherwise    = ValidationCache (\_ _ _ -> return ValidationCachePass)
                                       (\_ _ _ -> return ())

----------------------------------------------------------------

sendTLS :: Context -> ByteString -> IO ()
sendTLS ctx = sendData ctx . LBS.fromStrict

sendManyTLS :: Context -> [ByteString] -> IO ()
sendManyTLS ctx = sendData ctx . LBS.fromChunks

-- TLS version of recv (decrypting) without a cache.
recvTLS :: Context -> Recv
recvTLS ctx = E.handle onEOF $ recvData ctx
  where
    onEOF e
      | Just Error_EOF <- E.fromException e           = return ""
      | Just ioe <- E.fromException e, isEOFError ioe = return ""
      | otherwise                                     = E.throwIO e

----------------------------------------------------------------

getQUICParams :: HostName -> PortNumber -> ByteString -> ClientConfig
getQUICParams hostname port alpn = defaultClientConfig {
    ccServerName = hostname
  , ccPortName   = show port
  , ccALPN       = \_ -> return $ Just [alpn]
  , ccDebugLog   = True
  , ccValidate   = False
  , ccVersions   = [Version1]
  }
