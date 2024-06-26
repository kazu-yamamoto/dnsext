{-# LANGUAGE RecordWildCards #-}

module Monitor (
    monitor,
) where

-- GHC packages

import Control.Applicative ((<|>))
import Control.Concurrent (forkFinally, forkIO, getNumCapabilities, threadWaitRead)
import Control.Concurrent.Async (waitSTM)
import Control.Concurrent.STM (STM, atomically)
import Control.Monad (unless, void, when, (<=<))
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Char (toUpper)
import Data.Functor (($>))
import Data.List (find, isInfixOf)
import System.IO (
    Handle,
    IOMode (ReadWriteMode),
    hClose,
    hFlush,
    hGetLine,
    hIsEOF,
    hPutStr,
    hPutStrLn,
    stdin,
    stdout,
 )
import Text.Read (readMaybe)

-- dnsext-* packages
import DNS.Iterative.Internal (Env (..))
import DNS.Iterative.Server (HostName, PortNumber, withLocationIOE)
import qualified DNS.Log as Log
import qualified DNS.RRCache as Cache
import qualified DNS.ThreadStats as TStat
import qualified DNS.Types as DNS
import DNS.Types.Time (EpochTime)
import qualified Network.Socket as S

-- other packages
import Network.Socket (
    AddrInfo (..),
    SockAddr,
    Socket,
    SocketType (Stream),
 )
import UnliftIO.Exception (tryAny)

-- this package
import Config
import SocketUtil (ainfosSkipError)
import Types (Control (..))

monitorSockets :: PortNumber -> [HostName] -> IO [(Socket, SockAddr)]
monitorSockets port = mapM (aiSocket . (\(ai, _, _) -> ai)) <=< ainfosSkipError putStrLn Stream port
  where
    aiSocket ai =
        (,)
            <$> S.socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
            <*> pure (addrAddress ai)

data Command
    = Param
    | Find String
    | Lookup DNS.Domain DNS.TYPE
    | Stats
    | WStats
    | TStats
    | Expire EpochTime
    | Noop
    | Exit
    | Quit
    | Help (Maybe String)
    deriving (Show)

{- FOURMOLU_DISABLE -}
monitor
    :: Config
    -> Env
    -> Control
    -> IO [IO ()]
monitor conf env mng@Control{..} = do
    let monPort' = fromIntegral $ cnf_monitor_port conf
    ps <- monitorSockets monPort' $ cnf_monitor_addrs conf
    let ss = map fst ps
        v6only  sock  S.SockAddrInet6 {} = S.setSocketOption sock S.IPv6Only 1
        v6only _sock  _                  = pure ()
        servSock (sock, a) = withLocationIOE (show a ++ "/mon") $ do
            v6only sock a
            S.setSocketOption sock S.ReuseAddr 1
            S.bind sock a
            S.listen sock 5
    mapM_ servSock ps
    when (cnf_monitor_stdio conf) runStdConsole
    return $ map monitorServer ss
  where
    runStdConsole = do
        let repl = console conf env mng stdin stdout "<std>"
        void $ forkIO repl
    logLn level = logLines_ env level Nothing . (: [])
    handle onError = either onError return <=< tryAny
    monitorServer s = do
        let step = do
                socketWaitRead s
                (sock, addr) <- S.accept s
                sockh <- S.socketToHandle sock ReadWriteMode
                let repl = console conf env mng sockh sockh $ show addr
                void $ forkFinally repl (\_ -> hClose sockh)
            loop =
                either (const $ return ()) (const loop)
                    =<< withWait
                        waitQuit
                        (handle (logLn Log.WARN . ("monitor io-error: " ++) . show) step)
        loop
{- FOURMOLU_ENABLE -}

{- FOURMOLU_DISABLE -}
console
    :: Config
    -> Env
    -> Control
    -> Handle
    -> Handle
    -> String
    -> IO ()
console conf env Control{..} inH outH ainfo = do
    let input = do
            s <- hGetLine inH
            let err =
                    hPutStrLn
                        outH
                        ("monitor error: " ++ ainfo ++ ": command parse error: " ++ show s)
            maybe (err $> False) runCmd $ parseCmd $ words s

        step = do
            eof <- hIsEOF inH
            if eof then return True else input

        repl = do
            hPutStr outH "monitor> " *> hFlush outH
            either
                (const $ return ())
                (\exit -> unless exit repl)
                =<< withWait waitQuit (handle (($> False) . print) step)

    showParam outLn conf
    repl
  where
    handle onError = either onError return <=< tryAny

    parseTYPE s =
        find match types
      where
        us = map toUpper s
        match t = show t == us
        types = map DNS.toTYPE [1 .. 512]

    parseCmd [] = Just Noop
    parseCmd ws = case ws of
        "param" : _ -> Just Param
        "find" : s : _ -> Just $ Find s
        ["lookup", n, typ] -> Lookup (DNS.fromRepresentation n) <$> parseTYPE typ
        "stats" : _ -> Just Stats
        "t" : _ -> Just TStats
        "tstats" : _ -> Just TStats
        "w" : _ -> Just WStats
        "wstats" : _ -> Just WStats
        "expire" : args -> case args of
            [] -> Just $ Expire 0
            x : _ -> Expire <$> readMaybe x
        "exit" : _ -> Just Exit
        "quit-server" : _ -> Just Quit
        "help" : w : _ -> Just $ Help $ Just w
        "help" : [] -> Just $ Help Nothing
        _ -> Nothing

    outLn = hPutStrLn outH

    runCmd Quit = quitServer $> True
    runCmd Exit = return True
    runCmd cmd = dispatch cmd $> False
      where
        dispatch Param = showParam outLn conf
        dispatch Noop = return ()
        dispatch (Find s) =
            mapM_ outLn . filter (s `isInfixOf`) . map show . Cache.dump =<< getCache_ env
        dispatch (Lookup dom typ) = maybe (outLn "miss.") hit =<< lookupCache
          where
            lookupCache = do
                cache <- getCache_ env
                ts <- currentSeconds_ env
                return $ Cache.lookup ts dom typ DNS.IN cache
            hit (rrs, rank) = mapM_ outLn $ ("hit: " ++ show rank) : map show rrs
        dispatch Stats = toLazyByteString <$> getStats >>= BL.hPutStrLn outH
        dispatch TStats = unlines <$> TStat.dumpThreads >>= hPutStrLn outH
        dispatch WStats = toLazyByteString <$> getWStats >>= BL.hPutStrLn outH
        dispatch (Expire offset) = expireCache_ env . (+ offset) =<< currentSeconds_ env
        dispatch (Help w) = printHelp w
        dispatch x = outLn $ "command: unknown state: " ++ show x

    printHelp mw = case mw of
        Nothing -> hPutStr outH $ unlines [showHelp h | (_, h) <- helps]
        Just w ->
            maybe (outLn $ "unknown command: " ++ w) (outLn . showHelp) $ lookup w helps
      where
        showHelp (syn, msg) = syn ++ replicate (width - length syn) ' ' ++ " - " ++ msg
        width = 20
        helps =
            [ ("param", ("param", "show server parameters"))
            , ("find", ("find STRING", "find sub-string from dumped cache"))
            , ("lookup", ("lookup DOMAIN TYPE", "lookup cache"))
            , ("stats", ("stats", "show current server stats"))
            , ("wstats", ("wstats", "show worker thread status"))
            , ("expire", ("expire [SECONDS]", "expire cache at the time SECONDS later"))
            , ("exit", ("exit", "exit this management session"))
            , ("quit-server", ("quit-server", "quit this server"))
            , ("help", ("help", "show this help"))
            ]
{- FOURMOLU_ENABLE -}

withWait :: STM a -> IO b -> IO (Either a b)
withWait qstm blockAct =
    TStat.withAsync "monitor" blockAct $ \a ->
        atomically $
            (Left <$> qstm)
                <|> (Right <$> waitSTM a)

socketWaitRead :: Socket -> IO ()
socketWaitRead sock = S.withFdSocket sock $ threadWaitRead . fromIntegral

showParam :: (String -> IO ()) -> Config -> IO ()
showParam outLn conf = do
    mapM_ outLn $ showConfig conf
    n <- getNumCapabilities
    outLn $ "capabilities: " ++ show n
