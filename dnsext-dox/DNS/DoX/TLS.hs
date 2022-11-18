{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.TLS where

import qualified Control.Exception as E
import DNS.Do53.Client
import DNS.Do53.Internal
import DNS.Types
import qualified Data.ByteString as BS
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as LBS
import Data.Default.Class (def)
import Network.Socket hiding (recvBuf)
import qualified Network.TLS as TLS
import Network.TLS hiding (HostName)
import Network.TLS.Extra
import System.IO.Error (isEOFError)
import UnliftIO.Exception (throwIO, handle, fromException)

import Network.Socket.BufferPool

iij :: Question
iij = Question "www.iij.ad.jp" A classIN

dot :: HostName -> PortNumber -> Question -> IO ()
dot hostname port q = do
    E.bracket open close $ \sock ->
      E.bracket (contextNew sock params) bye $ \ctx -> do
        handshake ctx
        (recv, recvBuf) <- makeRecv $ recvTLS ctx
        recvN <- makeReceiveN "" recv recvBuf
        let sendDoT = sendVC (sendTLS ctx)
            recvDoT = recvVC recvN
        let qry = encodeQuery 100 q mempty
        sendDoT qry
        res <- recvDoT
        print res
  where
    params = getDefaultParams hostname False
    open = do
        ai <- makeAddrInfo (Just hostname) port
        sock <- openSocket ai

        let sockaddr = addrAddress ai
        connect sock sockaddr
        return sock

makeAddrInfo :: Maybe HostName -> PortNumber -> IO AddrInfo
makeAddrInfo maddr port = do
    let flgs = [AI_ADDRCONFIG, AI_NUMERICSERV, AI_PASSIVE]
        hints = defaultHints {
            addrFlags = flgs
          , addrSocketType = Stream
          }
    head <$> getAddrInfo (Just hints) maddr (Just $ show port)

getDefaultParams :: HostName -> Bool -> ClientParams
getDefaultParams serverName validate
    = (defaultParamsClient serverName "") {
    clientSupported = supported
  , clientWantSessionResume = Nothing
  , clientUseServerNameIndication = True
  , clientShared = shared
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
    validateCache
      | validate = def
      | otherwise    = ValidationCache (\_ _ _ -> return ValidationCachePass)
                                       (\_ _ _ -> return ())

sendTLS :: Context -> [BS.ByteString] -> IO ()
sendTLS ctx = sendData ctx . LBS.fromChunks

-- TLS version of recv (decrypting) without a cache.
recvTLS :: TLS.Context -> Recv
recvTLS ctx = handle onEOF $ TLS.recvData ctx
  where
    onEOF e
      | Just TLS.Error_EOF <- fromException e       = return ""
      | Just ioe <- fromException e, isEOFError ioe = return ""
      | otherwise                                   = throwIO e
