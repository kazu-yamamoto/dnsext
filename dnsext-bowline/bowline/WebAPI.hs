{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module WebAPI (new) where

import Control.Concurrent
import Data.ByteString ()
import qualified Network.HTTP.Types as HTTP
import Network.Socket
import Network.Wai
import Network.Wai.Handler.Warp
import qualified UnliftIO.Exception as E

import DNS.Iterative.Server (withLocationIOE)

import Config
import Types

doStats :: Control -> IO Response
doStats Control{..} = responseBuilder HTTP.ok200 [] <$> getStats

doWStats :: Control -> IO Response
doWStats Control{..} = responseBuilder HTTP.ok200 [] <$> getWStats

doReload :: Control -> Command -> IO Response
doReload Control{..} ctl = do
    setCommand ctl
    quitServer
    return ok

doQuit :: Control -> IO Response
doQuit Control{..} = do
    quitServer
    return ok

app :: Control -> Application
app mng req sendResp = getResp >>= sendResp
  where
    getResp
        | requestMethod req == HTTP.methodGet = case rawPathInfo req of
            "/metrics" -> doStats mng
            "/stats" -> doStats mng
            "/wstats" -> doWStats mng
            "/reload" -> doReload mng Reload
            "/keep-cache" -> doReload mng KeepCache
            "/quit" -> doQuit mng
            _ -> return $ ng HTTP.badRequest400
        | otherwise = return $ ng HTTP.methodNotAllowed405

ok :: Response
ok = responseLBS HTTP.ok200 [] "OK\n"

ng :: HTTP.Status -> Response
ng st = responseLBS st [] "NG\n"

new :: Config -> Control -> IO (Maybe ThreadId)
new Config{..} mng
    | cnf_webapi = Just <$> forkIO (runAPI cnf_webapi_addr cnf_webapi_port mng)
    | otherwise = return Nothing

runAPI :: String -> Int -> Control -> IO ()
runAPI addr port mng = withSocketsDo $ do
    ai <- resolve
    E.bracket (open ai) close $ \sock ->
        runSettingsSocket defaultSettings sock $ app mng
  where
    resolve = do
        let hints =
                defaultHints
                    { addrFlags = [AI_PASSIVE, AI_NUMERICHOST, AI_NUMERICSERV]
                    , addrSocketType = Stream
                    }
        head <$> getAddrInfo (Just hints) (Just addr) (Just $ show port)
    open ai = E.bracketOnError (openSocket ai) close $ \sock -> do
        setSocketOption sock ReuseAddr 1
        withFdSocket sock setCloseOnExecIfNeeded
        withLocationIOE (show ai ++ "/webapi") $ do
            bind sock $ addrAddress ai
            listen sock 32
        return sock
