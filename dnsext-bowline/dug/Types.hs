{-# LANGUAGE OverloadedStrings #-}

module Types where

import qualified DNS.Log as Log
import Data.ByteString.Short (ShortByteString)

import Output (OutputFlag (..))

data Options = Options
    { optHelp :: Bool
    , optIterative :: Bool
    , optDisableV6NS :: Bool
    , optPort :: Maybe String
    , optDoX :: ShortByteString
    , optFormat :: OutputFlag
    , optLogLevel :: Log.Level
    , optKeyLogFile :: Maybe FilePath
    , optResumptionFile :: Maybe FilePath
    , opt0RTT :: Bool
    }
    deriving (Show)

defaultOptions :: Options
defaultOptions =
    Options
        { optHelp = False
        , optIterative = False
        , optDisableV6NS = False
        , optPort = Nothing
        , optDoX = "do53"
        , optFormat = Singleline
        , optLogLevel = Log.WARN
        , optKeyLogFile = Nothing
        , optResumptionFile = Nothing
        , opt0RTT = False
        }
