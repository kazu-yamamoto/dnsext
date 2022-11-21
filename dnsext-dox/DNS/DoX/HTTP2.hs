{-# LANGUAGE OverloadedStrings #-}

module DNS.DoX.HTTP2 where

import Foreign.Marshal.Alloc (mallocBytes, free)
import qualified System.TimeManager as T
import DNS.Do53.Client
import DNS.Types
import DNS.Types.Decode
import Data.ByteString (ByteString)
import qualified Data.ByteString.Builder as BB
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LBS
import Data.Default.Class (def)
import Network.HTTP.Types
import qualified Network.HTTP2.Client as H2
import Network.Socket hiding (recvBuf)
import qualified Network.TLS as TLS
import Network.TLS hiding (HostName)
import Network.TLS.Extra
import System.IO.Error (isEOFError)
import qualified UnliftIO.Exception as E

import Network.Socket.BufferPool

import DNS.DoX.Common

doh :: HostName -> PortNumber -> Question -> IO ()
doh hostname port q = do
    E.bracket open close $ \sock ->
      E.bracket (contextNew sock params) bye $ \ctx -> do
        handshake ctx
        client ctx hostname qry
  where
    qry = encodeQuery 100 q mempty
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
        onSuggestALPN = return $ Just ["h2"]
      }
    validateCache
      | validate = def
      | otherwise    = ValidationCache (\_ _ _ -> return ValidationCachePass)
                                       (\_ _ _ -> return ())

sendTLS :: Context -> ByteString -> IO ()
sendTLS ctx = sendData ctx . LBS.fromStrict

-- TLS version of recv (decrypting) without a cache.
recvTLS :: TLS.Context -> Recv
recvTLS ctx = E.handle onEOF $ TLS.recvData ctx
  where
    onEOF e
      | Just TLS.Error_EOF <- E.fromException e       = return ""
      | Just ioe <- E.fromException e, isEOFError ioe = return ""
      | otherwise                                     = E.throwIO e

client :: Context -> HostName -> ByteString -> IO ()
client ctx hostname msg =
    E.bracket (allocConfig ctx 4096) freeConfig $ \conf -> H2.run cliconf conf cli
  where
    req = H2.requestBuilder methodPost "/dns-query" clientDoHHeaders $ BB.byteString msg
    cliconf = H2.ClientConfig {
        H2.scheme = "https"
      , H2.authority = C8.pack hostname
      , H2.cacheLimit = 20
      }
    cli sendRequest = sendRequest req $ \rsp -> do
        bs <- loop rsp ""
        print $ decode bs
      where
        loop rsp bs0 = do
            bs <- H2.getResponseBodyChunk rsp
            if bs == "" then return bs0
                        else loop rsp (bs0 <> bs)

allocConfig :: Context -> Int -> IO H2.Config
allocConfig ctx bufsiz = do
    buf <- mallocBytes bufsiz
    timmgr <- T.initialize $ 30 * 1000000
    (recv, recvBuf) <- makeRecv $ recvTLS ctx
    recvN <- makeReceiveN "" recv recvBuf
    let config = H2.Config {
            H2.confWriteBuffer = buf
          , H2.confBufferSize = bufsiz
          , H2.confSendAll = sendTLS ctx
          , H2.confReadN = recvN
          , H2.confPositionReadMaker = H2.defaultPositionReadMaker
          , H2.confTimeoutManager = timmgr
          }
    return config

-- | Deallocating the resource of the simple configuration.
freeConfig :: H2.Config -> IO ()
freeConfig conf = do
    free $ H2.confWriteBuffer conf
    T.killManager $ H2.confTimeoutManager conf
