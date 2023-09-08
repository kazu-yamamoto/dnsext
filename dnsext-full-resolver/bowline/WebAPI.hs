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
import Network.Wai
import Network.Wai.Handler.Warp
import Servant

newtype Status = Status { content :: String } deriving Generic

type StatusAPI = "status" :> Get '[JSON] Status

instance ToJSON Status

server :: IO String -> Server StatusAPI
server getStatus = Status <$> liftIO getStatus

statusAPI :: Proxy StatusAPI
statusAPI = Proxy

app :: IO String -> Application
app getStatus = serve statusAPI $ server getStatus

runAPI :: Int -> IO String -> IO ()
runAPI port getStatus = run port $ app getStatus
