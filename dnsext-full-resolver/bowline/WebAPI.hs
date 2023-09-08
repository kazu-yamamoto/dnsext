{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
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

newtype Status = Status { content :: String } deriving Generic

type StatusAPI = "status" :> Get '[JSON] Status

instance ToJSON Status

server :: IO String -> Server StatusAPI
server getStatus = Status <$> liftIO getStatus

statusAPI :: Proxy StatusAPI
statusAPI = Proxy

app :: IO String -> Application
app getStatus = serve statusAPI $ server getStatus

runAPI :: String -> Int -> IO String -> IO ()
runAPI addr port getStatus = withSocketsDo $ do
    ai <- resolve
    E.bracket (open ai) close $ \sock ->
      runSettingsSocket defaultSettings sock $ app getStatus
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
