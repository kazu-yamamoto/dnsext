{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}

module WebAPI (runAPI) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson
import GHC.Generics
import Network.Socket
import Network.Wai
import Network.Wai.Handler.Warp
import Servant
import qualified UnliftIO.Exception as E

import Manage

newtype Status = Status { content :: String } deriving Generic

type StatusAPI = "status" :> Get '[JSON] Status
            :<|> "reload" :> Get '[JSON] Status
            :<|> "quit" :> Get '[JSON] Status

instance ToJSON Status

server :: Manage -> Server StatusAPI
server mng@Manage{..} = Status <$> liftIO getStatus
                   :<|> reload mng
                   :<|> quit mng

reload :: Manage -> Handler Status
reload Manage{..} = do
    liftIO $ do
        setReload
        quitServer
    return $ Status "OK"

quit :: Manage -> Handler Status
quit Manage{..} = do
    liftIO $ quitServer
    return $ Status "OK"

statusAPI :: Proxy StatusAPI
statusAPI = Proxy

app :: Manage -> Application
app mng  = serve statusAPI $ server mng

runAPI :: String -> Int -> Manage -> IO ()
runAPI addr port mng = withSocketsDo $ do
    ai <- resolve
    E.bracket (open ai) close $ \sock ->
      runSettingsSocket defaultSettings sock $ app mng
  where
    resolve = do
        let hints = defaultHints {
                addrFlags = [AI_PASSIVE, AI_NUMERICHOST, AI_NUMERICSERV]
              , addrSocketType = Stream
              }
        head <$> getAddrInfo (Just hints) (Just addr) (Just $ show port)
    open ai = E.bracketOnError (openSocket ai) close $ \sock -> do
        setSocketOption sock ReuseAddr 1
        withFdSocket sock setCloseOnExecIfNeeded
        bind sock $ addrAddress ai
        listen sock 32
        return sock
