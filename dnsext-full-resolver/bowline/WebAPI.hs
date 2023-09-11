{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module WebAPI (runAPI) where

import Data.ByteString ()
import qualified Data.ByteString.Lazy.Char8 as LBS
import Network.HTTP.Types
import Network.Socket
import Network.Wai
import Network.Wai.Handler.Warp
import qualified UnliftIO.Exception as E

import Manage

doStatus :: Manage -> IO Response
doStatus Manage{..} = responseLBS ok200 [] . LBS.pack <$> getStatus

doReload :: Manage -> IO Response
doReload Manage{..} = do
    setReload
    quitServer
    return ok

doQuit :: Manage -> IO Response
doQuit Manage{..} = do
    quitServer
    return ok

app :: Manage -> Application
app mng req sendResp = getResp >>= sendResp
  where
    getResp
        | requestMethod req == methodGet = case rawPathInfo req of
            "/status" -> doStatus mng
            "/reload" -> doReload mng
            "/quit" -> doQuit mng
            _ -> return $ ng badRequest400
        | otherwise = return $ ng methodNotAllowed405

ok :: Response
ok = responseLBS ok200 [] "OK\n"

ng :: Status -> Response
ng st = responseLBS st [] "NG\n"

runAPI :: String -> Int -> Manage -> IO ()
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
        bind sock $ addrAddress ai
        listen sock 32
        return sock
