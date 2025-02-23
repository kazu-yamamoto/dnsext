{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module WebAPI (
    bindAPI,
    run,
    new,
) where

import Control.Concurrent
import qualified Control.Exception as E
import Data.ByteString ()
import Data.Functor
import qualified Data.List.NonEmpty as NE
import Data.String
import qualified Network.HTTP.Types as HTTP
import Network.Socket
import Network.Wai
import Network.Wai.Handler.Warp hiding (run)

import DNS.Iterative.Server (withLocationIOE)
import qualified DNS.ThreadStats as TStat

import Config
import Types

doStats :: Control -> IO Response
doStats Control{..} = responseBuilder HTTP.ok200 [] <$> getStats

doWStats :: Control -> IO Response
doWStats Control{..} = responseBuilder HTTP.ok200 [] <$> getWStats

{- FOURMOLU_DISABLE -}
doHelp :: IO Response
doHelp = return $ responseBuilder HTTP.ok200 [] txt
  where
    txt = fromString $ unlines $ "WebAPI help:" : "" : map (uncurry hline) helps
    helps =
        [ ("/metrics"     , "returns metrics info")
        , ("/wstats"      , "returns worker thread info")
        , ("/reopen-log"  , "reopen logfile when file logging")
        , ("/reload"      , "reload bowline without keeping cache")
        , ("/keep-cache"  , "reload bowline with keeping cache")
        , ("/quit"        , "quit bowline")
        , ("/help"        , "show this help texts")
        ]
    hline name note = name ++ replicate (width - length name) ' ' ++ note
    width = maximum (0 : map (length . fst) helps) + margin
    margin = 3
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
app :: Control -> Application
app mng req sendResp = getResp >>= sendResp
  where
    getResp
        | requestMethod req == HTTP.methodGet = case rawPathInfo req of
            "/metrics"     -> doStats mng
            "/stats"       -> doStats mng
            "/wstats"      -> doWStats mng
            "/reopen-log"  -> reopenLog mng $> ok
            "/reload"      -> quitCmd mng Reload     $> ok
            "/keep-cache"  -> quitCmd mng KeepCache  $> ok
            "/quit"        -> quitCmd mng Quit       $> ok
            "/help"        -> doHelp
            "/"            -> doHelp
            _ -> return $ ng HTTP.badRequest400
        | otherwise = return $ ng HTTP.methodNotAllowed405
{- FOURMOLU_ENABLE -}

ok :: Response
ok = responseLBS HTTP.ok200 [] "OK\n"

ng :: HTTP.Status -> Response
ng st = responseLBS st [] "NG\n"

{- FOURMOLU_DISABLE -}
bindAPI :: Config -> IO (Maybe Socket)
bindAPI Config{..}
    | cnf_webapi  = resolve >>= open <&> Just
    | otherwise   = return Nothing
  where
    resolve = do
        let hints =
                defaultHints
                    { addrFlags = [AI_PASSIVE, AI_NUMERICHOST, AI_NUMERICSERV]
                    , addrSocketType = Stream
                    }
        NE.head <$> getAddrInfo (Just hints) (Just cnf_webapi_addr) (Just $ show cnf_webapi_port)
    open ai = E.bracketOnError (openSocket ai) close $ \sock -> do
        setSocketOption sock ReuseAddr 1
        withFdSocket sock setCloseOnExecIfNeeded
        withLocationIOE (show ai ++ "/webapi") $ do
            bind sock $ addrAddress ai
            listen sock 32
        return sock
{- FOURMOLU_ENABLE -}

run :: Control -> Socket -> IO ()
run mng sock = E.finally (runSettingsSocket defaultSettings sock $ app mng) (close sock)

new :: Config -> Control -> IO (Maybe ThreadId)
new conf mng = mapM (TStat.forkIO "webapi-srv" . run mng) =<< bindAPI conf
